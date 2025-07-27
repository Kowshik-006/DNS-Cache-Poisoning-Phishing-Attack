#!/usr/bin/env python3
import socket
import struct
import threading
import time
import random
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, sr1, conf, sniff

# Disable Scapy warnings
conf.verb = 0

class FixedDNSServer:
    def __init__(self, listen_ip="0.0.0.0", listen_port=53, forwarder="8.8.8.8"):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.forwarder = forwarder
        self.cache = {}  # domain -> (ip, timestamp)
        self.pending_queries = {}  # txid -> (domain, client_addr, original_txid)
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
            print(f"[+] Fixed DNS Server started on {self.listen_ip}:{self.listen_port}")
            print(f"[+] Forwarding queries to {self.forwarder}")
            print(f"[+] VULNERABLE to cache poisoning - accepts spoofed responses")
            
            # Start packet capture thread
            capture_thread = threading.Thread(target=self.capture_responses)
            capture_thread.daemon = True
            capture_thread.start()
            
            # Main query handling loop
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(1024)
                    self.handle_query(data, addr)
                except Exception as e:
                    if self.running:
                        print(f"[-] Error receiving data: {e}")
                        
        except Exception as e:
            print(f"[-] Failed to start DNS server: {e}")
            
    def capture_responses(self):
        """Capture all DNS responses"""
        try:
            def packet_handler(packet):
                if (packet.haslayer(DNS) and packet.haslayer(UDP) and packet.haslayer(IP) and
                    packet[DNS].qr == 1 and packet[UDP].dport == 53):
                    
                    txid = packet[DNS].id
                    src_ip = packet[IP].src
                    
                    print(f"[CAPTURE] Response from {src_ip} (txid={txid})")
                    
                    # Check if this matches a pending query
                    if txid in self.pending_queries:
                        domain, client_addr, original_txid = self.pending_queries[txid]
                        del self.pending_queries[txid]
                        
                        print(f"[MATCH] Processing response for {domain}")
                        self.process_response(packet[DNS], domain, client_addr, original_txid)
                        
            # Start sniffing
            sniff(filter=f"udp and port 53 and dst host {self.listen_ip}", 
                  prn=packet_handler, 
                  store=0, 
                  stop_filter=lambda x: not self.running)
                  
        except Exception as e:
            print(f"[-] Error in packet capture: {e}")
            
    def handle_query(self, data, addr):
        """Handle incoming DNS query"""
        try:
            dns_packet = DNS(data)
            if dns_packet.qr == 0:  # Query
                query_name = dns_packet[DNSQR].qname.decode('utf-8').rstrip('.')
                query_type = dns_packet[DNSQR].qtype
                original_txid = dns_packet.id
                
                print(f"[QUERY] {addr[0]}:{addr[1]} -> {query_name} (type={query_type}, txid={original_txid})")
                
                # Check cache first
                cache_key = f"{query_name}:{query_type}"
                if cache_key in self.cache:
                    cached_ip, timestamp = self.cache[cache_key]
                    if time.time() - timestamp < 300:  # 5 minute cache
                        print(f"[CACHE] Returning cached result: {query_name} -> {cached_ip}")
                        response = self.create_response(dns_packet, cached_ip)
                        self.socket.sendto(response, addr)
                        return
                
                # Generate predictable txid for forwarding
                forwarded_txid = self.get_forwarded_txid(original_txid)
                
                # Store pending query
                self.pending_queries[forwarded_txid] = (query_name, addr, original_txid)
                print(f"[PENDING] Added: txid={forwarded_txid}, domain={query_name}")
                
                # Forward query
                self.forward_query(dns_packet, forwarded_txid)
                
        except Exception as e:
            print(f"[-] Error handling query: {e}")
            
    def get_forwarded_txid(self, original_txid):
        """Generate predictable txid for forwarding"""
        random.seed(original_txid)
        txid = random.randint(1, 10)
        random.seed()
        return txid
        
    def forward_query(self, dns_packet, forwarded_txid):
        """Forward query to upstream DNS"""
        try:
            # Create new packet with forwarded txid
            query = IP(dst=self.forwarder) / UDP(sport=53, dport=53) / dns_packet
            query[DNS].id = forwarded_txid
            
            print(f"[FORWARD] Querying {self.forwarder} with txid={forwarded_txid}")
            
            # Send query (response will be captured by sniff thread)
            sr1(query, timeout=1, verbose=0)
            
        except Exception as e:
            print(f"[-] Error forwarding query: {e}")
            
    def process_response(self, dns_packet, domain, client_addr, original_txid):
        """Process DNS response and send to client"""
        try:
            # Extract IP from response
            if dns_packet.haslayer(DNSRR):
                for rr in dns_packet[DNSRR]:
                    if rr.type == 1:  # A record
                        ip_address = rr.rdata
                        
                        # Cache the result
                        cache_key = f"{domain}:1"
                        self.cache[cache_key] = (ip_address, time.time())
                        print(f"[CACHE] Cached: {domain} -> {ip_address}")
                        
                        # If this is a spoofed response, also cache main domain
                        if ip_address == "10.0.0.10" and '.' in domain:
                            main_domain = domain.split('.', 1)[1]
                            main_cache_key = f"{main_domain}:1"
                            self.cache[main_cache_key] = ("10.0.0.10", time.time())
                            print(f"[CACHE] Cached main domain: {main_domain} -> 10.0.0.10")
                        
                        break
            
            # Create response with original txid
            response = dns_packet.copy()
            response.id = original_txid
            
            # Send to client
            self.socket.sendto(bytes(response), client_addr)
            print(f"[RESPONSE] Sent to {client_addr[0]}:{client_addr[1]} (txid={original_txid})")
            
        except Exception as e:
            print(f"[-] Error processing response: {e}")
            
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
        """Manually add entry to cache"""
        self.cache[f"{domain}:1"] = (ip_address, time.time())
        print(f"[CACHE] Manually added: {domain} -> {ip_address}")
        
    def clear_cache(self):
        """Clear the DNS cache"""
        self.cache.clear()
        self.pending_queries.clear()
        print("[CACHE] Cleared all cached entries")
        
    def show_cache(self):
        """Show current cache contents"""
        print("\n=== DNS Cache Contents ===")
        for key, (ip, timestamp) in self.cache.items():
            domain = key.split(':')[0]
            age = time.time() - timestamp
            print(f"{domain} -> {ip} (age: {age:.1f}s)")
        print("==========================\n")
        
    def stop(self):
        """Stop the DNS server"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("[+] DNS Server stopped")

def main():
    # Create and start DNS server
    dns_server = FixedDNSServer(
        listen_ip="0.0.0.0",  # Listen on all interfaces
        listen_port=53,
        forwarder="8.8.8.8"
    )
    
    try:
        # Start server in background thread
        server_thread = threading.Thread(target=dns_server.start)
        server_thread.daemon = True
        server_thread.start()
        
        print("\n=== Fixed DNS Server Control ===")
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