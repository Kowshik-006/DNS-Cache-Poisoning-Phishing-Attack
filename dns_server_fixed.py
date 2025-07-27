#!/usr/bin/env python3
import socket
import struct
import threading
import time
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, sr1, conf

# Disable Scapy warnings
conf.verb = 0

class CustomDNSServer:
    def __init__(self, listen_ip="0.0.0.0", listen_port=53, forwarder="8.8.8.8", attack_delay=0.2):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.forwarder = forwarder
        self.attack_delay = attack_delay  # Delay to allow spoofed responses
        self.cache = {}  # Simple cache: domain -> (ip, timestamp)
        self.pending_queries = {}  # Track pending queries: txid -> (domain, client_addr)
        self.original_txids = {}  # Track original client TXIDs: (domain, client_addr) -> original_txid
        self.running = False
        self.socket = None
        
    def start(self):
        """Start the DNS server"""
        try:
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.listen_ip, self.listen_port))
            
            self.running = True
            print(f"[+] Custom DNS Server started on {self.listen_ip}:{self.listen_port}")
            print(f"[+] Forwarding queries to {self.forwarder}")
            print(f"[+] VULNERABLE to cache poisoning - accepts spoofed responses")
            
            # Start packet capture thread for spoofed responses
            capture_thread = threading.Thread(target=self.capture_spoofed_responses)
            capture_thread.daemon = True
            capture_thread.start()
            
            # Start listening for queries and responses
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(1024)
                    # Handle each packet in a separate thread
                    thread = threading.Thread(target=self.handle_packet, args=(data, addr))
                    thread.daemon = True
                    thread.start()
                except Exception as e:
                    if self.running:
                        print(f"[-] Error receiving data: {e}")
                        
        except Exception as e:
            print(f"[-] Failed to start DNS server: {e}")
            
    def capture_spoofed_responses(self):
        """Capture spoofed DNS responses using Scapy"""
        try:
            from scapy.all import sniff, DNS, UDP, IP
            
            def packet_handler(packet):
                if packet.haslayer(DNS) and packet.haslayer(UDP) and packet.haslayer(IP):
                    # Check if this is a DNS response to our server
                    if (packet[DNS].qr == 1 and  # Response
                        packet[UDP].dport == 53 and  # Destined for DNS
                        packet[IP].dst == self.listen_ip):  # To our server
                        
                        print(f"[CAPTURE] DNS response from {packet[IP].src}:{packet[UDP].sport} (txid={packet[DNS].id})")
                        
                        # Check if this looks like a spoofed response
                        is_spoofed = False
                        if packet[DNS].haslayer(DNSRR):
                            for rr in packet[DNS][DNSRR]:
                                if rr.type == 1 and rr.rdata == "10.0.0.10":  # A record with attacker IP
                                    is_spoofed = True
                                    break
                        
                        if is_spoofed:
                            print(f"[CAPTURE] *** SPOOFED RESPONSE DETECTED ***")
                            # Only process spoofed responses in capture thread
                            fake_addr = (packet[IP].src, packet[UDP].sport)
                            self.handle_response(packet[DNS], fake_addr)
                        else:
                            print(f"[CAPTURE] Real response from authoritative server - processing in capture thread")
                            # Process real responses in capture thread for normal DNS lookups
                            fake_addr = (packet[IP].src, packet[UDP].sport)
                            self.handle_response(packet[DNS], fake_addr)
            
            # Start sniffing for DNS responses
            sniff(filter=f"udp and port 53 and dst host {self.listen_ip}", 
                  prn=packet_handler, 
                  store=0, 
                  stop_filter=lambda x: not self.running)
                  
        except Exception as e:
            print(f"[-] Error in packet capture: {e}")
            
    def stop(self):
        """Stop the DNS server"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("[+] DNS Server stopped")
        
    def handle_packet(self, data, addr):
        """Handle incoming DNS packets (queries only)"""
        try:
            # Parse DNS packet
            dns_packet = DNS(data)
            
            # Only handle queries (QR=0) - responses are handled by capture thread
            if dns_packet.qr == 0:
                # This is a query - handle it
                self.handle_query(dns_packet, addr)
            else:
                # This is a response - ignore it in main thread (handled by capture thread)
                print(f"[IGNORE] Response received in main thread - ignoring (txid={dns_packet.id})")
                
        except Exception as e:
            print(f"[-] Error handling packet: {e}")
            

    def handle_query(self, dns_packet, addr):
        """Handle a DNS query from client"""
        try:
            query_name = dns_packet[DNSQR].qname.decode('utf-8').rstrip('.')
            query_type = dns_packet[DNSQR].qtype
            txid = dns_packet.id
            
            print(f"[QUERY] {addr[0]}:{addr[1]} -> {query_name} (type={query_type}, txid={txid})")
            
            # Check cache first
            normalized_query = self.normalize_domain(query_name)
            cache_key = f"{normalized_query}:{query_type}"
            print(f"[DEBUG] Looking for cache key: {cache_key}")
            print(f"[DEBUG] Available cache keys: {list(self.cache.keys())}")
            if cache_key in self.cache:
                cached_ip, timestamp = self.cache[cache_key]
                if time.time() - timestamp < 400:  # 5 minute cache
                    print(f"[CACHE] Returning cached result: {normalized_query} -> {cached_ip}")
                    response = self.create_response(dns_packet, cached_ip)
                    self.socket.sendto(response, addr)
                    return
                else:
                    print(f"[DEBUG] Cache entry expired for {cache_key}")
            else:
                print(f"[DEBUG] Cache miss for {cache_key}")
            
            # Store pending query for response matching (use the forwarded txid)
            # Get the actual txid that will be used when forwarding
            forwarded_txid = self.get_forwarded_txid(dns_packet, self.forwarder)
            self.pending_queries[forwarded_txid] = (query_name, addr)
            
            # Store original client TXID for response
            self.original_txids[(query_name, addr)] = txid
            
            print(f"[PENDING] Added pending query: txid={forwarded_txid}, domain={query_name}")
            print(f"[PENDING] Current pending queries: {list(self.pending_queries.keys())}")
            
            # Add small delay to allow spoofed responses to arrive first
            time.sleep(self.attack_delay)  # Configurable delay
            
            # Forward query to upstream DNS
            print(f"[FORWARD] Querying {self.forwarder} for {query_name} (txid={txid})")
            response = self.forward_query(dns_packet, self.forwarder)
            
            if response:
                # Check if we already got a spoofed response
                if forwarded_txid in self.pending_queries:
                    print(f"[IGNORE] Real response ignored - already handled by spoofed response")
                    return
                
                # Check if the main domain is already poisoned (only for subdomain queries)
                if '.' in query_name:
                    main_domain = query_name.split('.', 1)[1]
                    main_cache_key = f"{main_domain}:1"
                    if main_cache_key in self.cache and self.cache[main_cache_key][0] == "10.0.0.10":
                        print(f"[IGNORE] Real response ignored - main domain {main_domain} already poisoned")
                        return
                
                # Cache the result
                if query_type == 1:  # A record
                    try:
                        response_dns = DNS(response)
                        if response_dns.an and response_dns.an.rdata:
                            cached_ip = response_dns.an.rdata
                            self.cache[cache_key] = (cached_ip, time.time())
                            print(f"[CACHE] Cached: {query_name} -> {cached_ip}")
                    except:
                        pass
                
                # Send response back to client
                self.socket.sendto(response, addr)
                print(f"[RESPONSE] Sent response to {addr[0]}:{addr[1]}")
            else:
                print(f"[-] No response from {self.forwarder}")
                
        except Exception as e:
            print(f"[-] Error handling query: {e}")
            
    def handle_response(self, dns_packet, addr):
        """Handle a DNS response (including spoofed ones)"""
        try:
            txid = dns_packet.id
            print(f"[RESPONSE] Received response from {addr[0]}:{addr[1]} (txid={txid})")
            
            # Check if this matches a pending query
            if txid in self.pending_queries:
                query_name, client_addr = self.pending_queries[txid]
                del self.pending_queries[txid]  # Remove from pending
                print(f"[MATCH] Response matches pending query for {query_name}")
                
                # Process the response and cache it
                if dns_packet.haslayer(DNSRR):
                    print(f"[DEBUG] Response has {len(dns_packet[DNSRR])} DNSRR records")
                    for i, rr in enumerate(dns_packet[DNSRR]):
                        print(f"[DEBUG] Record {i}: type={rr.type}, name={rr.rrname}, data={rr.rdata}")
                        if rr.type == 1:  # A record
                            cached_ip = rr.rdata
                            # Normalize domain names for consistent caching
                            normalized_query = self.normalize_domain(query_name)
                            normalized_record = self.normalize_domain(rr.rrname)
                            
                            # Cache the subdomain that was queried
                            cache_key = f"{normalized_query}:1"
                            old_cache = self.cache.get(cache_key, "NOT_CACHED")
                            self.cache[cache_key] = (cached_ip, time.time())
                            print(f"[CACHE] Cached subdomain: {normalized_query} -> {cached_ip} (was: {old_cache})")
                            
                            # Also cache the exact domain name from the DNS record
                            record_cache_key = f"{normalized_record}:1"
                            self.cache[record_cache_key] = (cached_ip, time.time())
                            print(f"[CACHE] Also cached record name: {normalized_record} -> {cached_ip}")
                            
                            # If this is a spoofed response (attacker IP), also cache the main domain
                            if cached_ip == "10.0.0.10":
                                if '.' in normalized_query:
                                    main_domain = normalized_query.split('.', 1)[1]
                                    # Cache both A and AAAA records for the main domain
                                    main_cache_key_a = f"{main_domain}:1"
                                    main_cache_key_aaaa = f"{main_domain}:28"
                                    self.cache[main_cache_key_a] = ("10.0.0.10", time.time())
                                    self.cache[main_cache_key_aaaa] = ("10.0.0.10", time.time())
                                    print(f"[CACHE] Cached main domain (spoofed): {main_domain} -> 10.0.0.10 (A and AAAA)")
                                else:
                                    # If it's already the main domain, cache both A and AAAA
                                    main_cache_key_a = f"{normalized_query}:1"
                                    main_cache_key_aaaa = f"{normalized_query}:28"
                                    self.cache[main_cache_key_a] = ("10.0.0.10", time.time())
                                    self.cache[main_cache_key_aaaa] = ("10.0.0.10", time.time())
                                    print(f"[CACHE] Cached main domain directly: {normalized_query} -> 10.0.0.10 (A and AAAA)")
                            
                        elif rr.type == 2:  # NS record
                            # Cache the NS record for the main domain
                            ns_domain = self.normalize_domain(rr.rrname)
                            ns_data = rr.rdata.decode('utf-8') if isinstance(rr.rdata, bytes) else str(rr.rdata)
                            ns_cache_key = f"{ns_domain}:2"  # Type 2 = NS record
                            self.cache[ns_cache_key] = (ns_data, time.time())
                            print(f"[CACHE] Cached NS record: {ns_domain} -> {ns_data}")
                            
                        else:
                            print(f"[DEBUG] Skipping record: type={rr.type}")
                else:
                    print(f"[DEBUG] Response has no DNSRR records")
                
                # Create response with original client TXID
                response_packet = dns_packet.copy()
                response_packet.id = self.get_original_txid(query_name, client_addr)
                
                # Forward response to original client
                self.socket.sendto(bytes(response_packet), client_addr)
                print(f"[FORWARD] Forwarded response to {client_addr[0]}:{client_addr[1]} with original TXID")
                return  # Exit early to prevent duplicate processing
            else:
                print(f"[IGNORE] Response with txid={txid} doesn't match any pending query")
                
        except Exception as e:
            print(f"[-] Error handling response: {e}")
            

    def normalize_domain(self, domain):
        """Normalize domain name (remove trailing dot, lowercase)"""
        if isinstance(domain, bytes):
            domain = domain.decode('utf-8')
        return domain.rstrip('.').lower()
        
    def get_forwarded_txid(self, dns_packet, forwarder):
        """Get the txid that will be used when forwarding the query"""
        import random
        # Use the same random seed to ensure consistency
        random.seed(hash(dns_packet.id) % 1000)  # Use original txid as seed
        txid = random.randint(1, 30)
        random.seed()  # Reset seed
        return txid
        
    def get_original_txid(self, query_name, client_addr):
        """Get the original client TXID for a query"""
        key = (query_name, client_addr)
        if key in self.original_txids:
            original_txid = self.original_txids[key]
            del self.original_txids[key]  # Clean up
            return original_txid
        return None
        
    def forward_query(self, dns_packet, forwarder):
        """Forward DNS query to upstream server (synchronous version)"""
        try:
            # Create packet to forward with limited txid range (1-5) for testing
            import random
            # Use the same random seed to ensure consistency with get_forwarded_txid
            random.seed(hash(dns_packet.id) % 1000)  # Use original txid as seed
            test_txid = random.randint(1, 30)
            random.seed()  # Reset seed
            
            # Create new packet with test txid
            query = IP(dst=forwarder) / UDP(sport=53, dport=53) / dns_packet
            query[DNS].id = test_txid
            
            print(f"[TEST] Using txid={test_txid} for query to {forwarder}")
            
            # Send query and wait for response
            response = sr1(query, timeout=2, verbose=0)
            
            if response and response.haslayer(DNS):
                return bytes(response[DNS])
            else:
                return None
                
        except Exception as e:
            print(f"[-] Error forwarding query: {e}")
            return None
            
    def create_response(self, original_packet, ip_address):
        """Create a DNS response packet"""
        try:
            response = DNS(
                id=original_packet.id,
                qr=1,  # Response
                aa=0,  # Not authoritative
                tc=0,  # Not truncated
                rd=1,  # Recursion desired
                ra=1,  # Recursion available
                z=0,
                rcode=0,  # No error
                qd=original_packet.qd,
                an=DNSRR(
                    rrname=original_packet.qd.qname,
                    type=1,  # A record
                    rclass=1,  # IN class
                    ttl=300,  # 5 minutes
                    rdata=ip_address
                )
            )
            return bytes(response)
        except Exception as e:
            print(f"[-] Error creating response: {e}")
            return None
            
    def add_to_cache(self, domain, ip_address):
        """Manually add entry to cache (for testing)"""
        # Add both A and AAAA records
        self.cache[f"{domain}:1"] = (ip_address, time.time())
        self.cache[f"{domain}:28"] = (ip_address, time.time())
        print(f"[CACHE] Manually added: {domain} -> {ip_address} (A and AAAA records)")
        
    def clear_cache(self):
        """Clear the DNS cache"""
        self.cache.clear()
        self.pending_queries.clear()
        self.original_txids.clear()
        print("[CACHE] Cleared all cached entries and pending queries")
        
    def show_cache(self):
        """Show current cache contents"""
        print("\n=== DNS Cache Contents ===")
        for key, (ip, timestamp) in self.cache.items():
            domain = key.split(':')[0]
            age = time.time() - timestamp
            print(f"{domain} -> {ip} (age: {age:.1f}s)")
        print("==========================\n")

def main():
    # Create and start DNS server
    dns_server = CustomDNSServer(
        listen_ip="10.0.0.53",  # Your DNS server IP
        listen_port=53,
        forwarder="8.8.8.8"     # Only forward to 8.8.8.8
    )
    
    try:
        # Start server in background thread
        server_thread = threading.Thread(target=dns_server.start)
        server_thread.daemon = True
        server_thread.start()
        
        print("\n=== Custom DNS Server Control ===")
        print("Commands:")
        print("  cache - Show cache contents")
        print("  clear - Clear cache")
        print("  add <domain> <ip> - Add to cache")
        print("  quit - Stop server")
        print("===============================\n")
        
        # Command loop
        while True:
            try:
                cmd = input("DNS> ").strip().split()
                if not cmd:
                    continue
                    
                if cmd[0] == "cache":
                    dns_server.show_cache()
                elif cmd[0] == "clear":
                    dns_server.clear_cache()
                elif cmd[0] == "add" and len(cmd) == 3:
                    dns_server.add_to_cache(cmd[1], cmd[2])
                elif cmd[0] == "quit":
                    break
                else:
                    print("Unknown command. Use: cache, clear, add <domain> <ip>, or quit")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
                
    finally:
        dns_server.stop()

if __name__ == "__main__":
    main() 