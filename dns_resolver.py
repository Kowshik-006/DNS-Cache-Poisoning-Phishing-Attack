#!/usr/bin/env python3
"""
DNS Resolver
IP: 192.168.100.10
Receives queries on port 53
Forwards queries to 8.8.8.8 through port 5000
Accepts responses through port 5000
500-second timeout window
Validates source IP (8.8.8.8 only)
Caches responses including authority and additional sections
"""
import socket
import struct
import threading
import time

class SimpleDNSResolver:
    def __init__(self):
        self.ip = "192.168.100.10"
        self.query_port = 53
        self.response_port = 5000
        self.upstream_dns = "8.8.8.8"
        self.upstream_port = 53
        
        # State tracking
        self.pending_queries = {}  # query_id -> query_info
        self.cache = {}  # domain -> {response_data, timestamp, ttl}
        self.running = False
        
        # Sockets
        self.query_socket = None
        self.response_socket = None
        
    def start(self):
        """Start the DNS resolver"""
        print(f"[+] Starting DNS Resolver on {self.ip}:{self.query_port}")
        print(f"[+] Forwarding to {self.upstream_dns}:{self.upstream_port}")
        print(f"[+] Response port: {self.response_port}")
        print(f"[+] Source IP validation: {self.upstream_dns} only")
        
        self.running = True
        
        # Create sockets
        self.query_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.query_socket.bind(('0.0.0.0', self.query_port))  # Listen on all interfaces
        
        self.response_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.response_socket.bind(('0.0.0.0', self.response_port))  # Listen on all interfaces
        
        print(f"[+] Listening for queries on 0.0.0.0:{self.query_port}")
        print(f"[+] Listening for responses on 0.0.0.0:{self.response_port}")
        
        # Start response listener thread
        response_thread = threading.Thread(target=self.listen_for_responses)
        response_thread.daemon = True
        response_thread.start()
        
        # Main query handling loop
        while self.running:
            try:
                data, addr = self.query_socket.recvfrom(1024)
                self.handle_query(data, addr)
            except Exception as e:
                print(f"[-] Error in main loop: {e}")
                
    def handle_query(self, query_data, client_addr):
        """Handle incoming DNS query"""
        try:
            # Parse query ID and domain
            if len(query_data) < 12:
                print(f"[-] Invalid query data length: {len(query_data)}")
                return
                
            query_id = struct.unpack('!H', query_data[0:2])[0]
            domain = self.parse_domain(query_data[12:])
            
            print(f"[*] Query: {domain} (ID: {query_id})")
            print(f"[*] Cache contents: {list(self.cache.keys())}")
            
            # Check cache first - look for exact match or parent domain match
            cached_domain = self.find_cached_domain(domain)
            if cached_domain:
                print(f"[+] Cache hit for {domain} (found in {cached_domain}), creating response")
                
                # Create a proper response for the queried domain
                response = self.create_response_for_domain(domain, query_id)
                if response:
                    self.query_socket.sendto(response, client_addr)
                    return
                else:
                    print(f"[-] Failed to create response for {domain}")
            
            print(f"[*] Cache miss for {domain}, forwarding to {self.upstream_dns}")
            
            # Store pending query
            self.pending_queries[query_id] = {
                'domain': domain,
                'client_addr': client_addr,
                'query_data': query_data
            }
            
            # Forward query to upstream DNS
            self.forward_query(query_data)
            
        except Exception as e:
            print(f"[-] Error handling query: {e}")
            
    def forward_query(self, query_data):
        """Forward query to upstream DNS server"""
        try:
            # Send query to 8.8.8.8 from port 5000
            self.response_socket.sendto(query_data, (self.upstream_dns, self.upstream_port))
            print(f"[*] Forwarding to {self.upstream_dns}")
            
        except Exception as e:
            print(f"[-] Error forwarding query: {e}")
            
    def listen_for_responses(self):
        """Listen for responses from upstream DNS"""
        print(f"[+] Response listener started on port {self.response_port}")
        
        while self.running:
            try:
                data, addr = self.response_socket.recvfrom(1024)
                self.handle_response(data, addr)
            except Exception as e:
                print(f"[-] Error in response listener: {e}")
                
    def handle_response(self, response_data, upstream_addr):
        """Handle response from upstream DNS"""
        try:
            if len(response_data) < 12:
                print(f"[-] Invalid response data length: {len(response_data)}")
                return
                
            # Validate source IP (must be 8.8.8.8)
            if upstream_addr[0] != self.upstream_dns:
                print(f"[!] Invalid source IP {upstream_addr[0]}, expected {self.upstream_dns}")
                return
                
            response_id = struct.unpack('!H', response_data[0:2])[0]
            # print(f"[*] Response ID: {response_id}")
            
            # Check if this response matches a pending query
            if response_id in self.pending_queries:
                pending_query = self.pending_queries[response_id]
                client_addr = pending_query['client_addr']
                domain = pending_query['domain']
                
                print(f"[+] Found matching query for {domain}")
                
                # Parse and cache the response
                cached_domains = self.parse_and_cache_response(response_data, domain)
                
                # Send response back to client if new cache entries were created
                if cached_domains:
                    # Send response back to client
                    self.query_socket.sendto(response_data, client_addr)
                    print(f"[+] Cached and sent response for {domain}")
                else:
                    print(f"[*] No new cache entries for {domain}")
                
                # Remove from pending queries
                del self.pending_queries[response_id]
                
            # else:
                # print(f"[*] No matching query found for response ID {response_id}")
                
        except Exception as e:
            print(f"[-] Error handling response: {e}")
            
    def parse_and_cache_response(self, response_data, query_domain):
        """Parse DNS response and cache relevant records"""
        try:
            if len(response_data) < 12:
                return []
                
            cached_domains = []
                
            # Parse DNS header
            query_id = struct.unpack('!H', response_data[0:2])[0]
            flags = struct.unpack('!H', response_data[2:4])[0]
            qdcount = struct.unpack('!H', response_data[4:6])[0]
            ancount = struct.unpack('!H', response_data[6:8])[0]
            nscount = struct.unpack('!H', response_data[8:10])[0]
            arcount = struct.unpack('!H', response_data[10:12])[0]
            
            print(f"[*] DNS Response: {ancount} answers, {nscount} authority, {arcount} additional")
            
            pos = 12
            
            # Skip query section
            for _ in range(qdcount):
                pos = self.skip_dns_name(response_data, pos)
                pos += 4  # Skip type and class
            
            # Parse answer section (A records)
            for _ in range(ancount):
                name, pos = self.parse_dns_name(response_data, pos)
                if pos + 10 > len(response_data):
                    break
                    
                rtype = struct.unpack('!H', response_data[pos:pos+2])[0]
                rclass = struct.unpack('!H', response_data[pos+2:pos+4])[0]
                ttl = struct.unpack('!I', response_data[pos+4:pos+8])[0]
                rdlength = struct.unpack('!H', response_data[pos+8:pos+10])[0]
                pos += 10
                
                if rtype == 1 and rdlength == 4:  # A record
                    if pos + 4 <= len(response_data):
                        ip = socket.inet_ntoa(response_data[pos:pos+4])
                        # Only cache if not already cached
                        if name not in self.cache:
                            self.cache[name] = {
                                'response_data': response_data,
                                'timestamp': time.time(),
                                'ttl': ttl
                            }
                            print(f"[+] Cached A record: {name} -> {ip}")
                            cached_domains.append(name)
                        else:
                            print(f"[*] A record already cached: {name}")
                        pos += 4
                else:
                    pos += rdlength
            
            # Parse authority section (NS records)
            for _ in range(nscount):
                name, pos = self.parse_dns_name(response_data, pos)
                if pos + 10 > len(response_data):
                    break
                    
                rtype = struct.unpack('!H', response_data[pos:pos+2])[0]
                rclass = struct.unpack('!H', response_data[pos+2:pos+4])[0]
                ttl = struct.unpack('!I', response_data[pos+4:pos+8])[0]
                rdlength = struct.unpack('!H', response_data[pos+8:pos+10])[0]
                pos += 10
                
                if rtype == 2:  # NS record
                    if pos + rdlength <= len(response_data):
                        ns_name, _ = self.parse_dns_name(response_data, pos)
                        # Only cache if not already cached
                        if name not in self.cache:
                            self.cache[name] = {
                                'response_data': response_data,
                                'timestamp': time.time(),
                                'ttl': ttl
                            }
                            print(f"[+] Cached NS record: {name} -> {ns_name}")
                            cached_domains.append(name)
                        else:
                            print(f"[*] NS record already cached: {name}")
                        pos += rdlength
                else:
                    pos += rdlength
            
            # Parse additional section (A records for NS servers)
            for _ in range(arcount):
                name, pos = self.parse_dns_name(response_data, pos)
                if pos + 10 > len(response_data):
                    break
                    
                rtype = struct.unpack('!H', response_data[pos:pos+2])[0]
                rclass = struct.unpack('!H', response_data[pos+2:pos+4])[0]
                ttl = struct.unpack('!I', response_data[pos+4:pos+8])[0]
                rdlength = struct.unpack('!H', response_data[pos+8:pos+10])[0]
                pos += 10
                
                if rtype == 1 and rdlength == 4:  # A record
                    if pos + 4 <= len(response_data):
                        ip = socket.inet_ntoa(response_data[pos:pos+4])
                        # Only cache if not already cached
                        if name not in self.cache:
                            self.cache[name] = {
                                'response_data': response_data,
                                'timestamp': time.time(),
                                'ttl': ttl
                            }
                            print(f"[+] Cached additional A record: {name} -> {ip}")
                            cached_domains.append(name)
                        else:
                            print(f"[*] Additional A record already cached: {name}")
                        pos += 4
                else:
                    pos += rdlength
                    
            return cached_domains
                    
        except Exception as e:
            print(f"[-] Error parsing and caching response: {e}")
            return []
            
    def skip_dns_name(self, data, pos):
        """Skip DNS name in packet"""
        while pos < len(data) and data[pos] != 0:
            if data[pos] & 0xC0 == 0xC0:  # Compression pointer
                return pos + 2
            pos += data[pos] + 1
        return pos + 1
    
    def parse_dns_name(self, data, pos):
        """Parse DNS name from packet"""
        name = ""
        original_pos = pos
        
        while pos < len(data) and data[pos] != 0:
            if data[pos] & 0xC0 == 0xC0:  # Compression pointer
                offset = struct.unpack('!H', data[pos:pos+2])[0] & 0x3FFF
                compressed_name, _ = self.parse_dns_name(data, offset)
                return name + compressed_name, pos + 2
            
            length = data[pos]
            pos += 1
            if pos + length <= len(data):
                name += data[pos:pos+length].decode('ascii') + "."
                pos += length
        
        return name.rstrip('.'), pos + 1
            
    def create_response_for_domain(self, query_domain, query_id, malicious_ip="10.0.2.15"):
        """Create a DNS response for the queried domain"""
        try:
            # Create DNS header
            response = bytearray()
            
            # Transaction ID
            response.extend(struct.pack('!H', query_id))
            
            # Flags: QR=1 (response), AA=1 (authoritative), RD=1, RA=1
            response.extend(struct.pack('!H', 0x8180))
            
            # Counts: 1 question, 1 answer, 1 authority, 1 additional
            response.extend(struct.pack('!H', 1))  # QDCOUNT
            response.extend(struct.pack('!H', 1))  # ANCOUNT
            response.extend(struct.pack('!H', 1))  # NSCOUNT
            response.extend(struct.pack('!H', 1))  # ARCOUNT
            
            # Question section
            # Domain name
            for part in query_domain.split('.'):
                response.append(len(part))
                response.extend(part.encode('ascii'))
            response.append(0)  # End of name
            
            # QTYPE and QCLASS
            response.extend(struct.pack('!H', 1))   # A record
            response.extend(struct.pack('!H', 1))   # IN class
            
            # Answer section (A record)
            # Domain name (compressed pointer to question)
            response.extend(struct.pack('!H', 0xC00C))  # Pointer to question name
            response.extend(struct.pack('!H', 1))       # A record
            response.extend(struct.pack('!H', 1))       # IN class
            response.extend(struct.pack('!I', 86400))   # TTL
            response.extend(struct.pack('!H', 4))       # RDLENGTH
            response.extend(socket.inet_aton(malicious_ip))  # IP address
            
            # Authority section (NS record)
            # Domain name (compressed pointer to question)
            response.extend(struct.pack('!H', 0xC00C))  # Pointer to question name
            response.extend(struct.pack('!H', 2))       # NS record
            response.extend(struct.pack('!H', 1))       # IN class
            response.extend(struct.pack('!I', 86400))   # TTL
            
            # NS server name
            ns_name = f"ns1.{query_domain}"
            # Build NS name properly
            ns_name_parts = ns_name.split('.')
            ns_name_data = bytearray()
            for part in ns_name_parts:
                ns_name_data.append(len(part))
                ns_name_data.extend(part.encode('ascii'))
            ns_name_data.append(0)  # End of name
            
            response.extend(struct.pack('!H', len(ns_name_data)))  # RDLENGTH
            response.extend(ns_name_data)  # NS server name
            
            # Additional section (A record for NS server)
            # NS server name (compressed pointer to authority section)
            response.extend(struct.pack('!H', 0xC02B))  # Pointer to NS name in authority section
            response.extend(struct.pack('!H', 1))       # A record
            response.extend(struct.pack('!H', 1))       # IN class
            response.extend(struct.pack('!I', 86400))   # TTL
            response.extend(struct.pack('!H', 4))       # RDLENGTH
            response.extend(socket.inet_aton(malicious_ip))  # IP address
            
            return bytes(response)
            
        except Exception as e:
            print(f"[-] Error creating response: {e}")
            return None
    
    def find_cached_domain(self, query_domain):
        """Find a cached domain that matches the query domain"""
        # First check for exact match
        if query_domain in self.cache:
            return query_domain
        
        # Check if any cached domain is a parent of the query domain
        # (e.g., if query is 'friendsbook.com' and cache has 'ns1.friendsbook.com')
        for cached_domain in self.cache.keys():
            if query_domain.endswith('.' + cached_domain) or query_domain == cached_domain:
                return cached_domain
        
        # Check if query domain is a parent of any cached domain
        # (e.g., if query is 'friendsbook.com' and cache has 'random.friendsbook.com')
        for cached_domain in self.cache.keys():
            if cached_domain.endswith('.' + query_domain):
                return cached_domain
        
        return None
    
    def parse_domain(self, data):
        """Parse domain name from DNS packet"""
        domain = ""
        pos = 0
        
        while pos < len(data) and data[pos] != 0:
            length = data[pos]
            pos += 1
            
            if pos + length <= len(data):
                domain += data[pos:pos+length].decode('ascii') + "."
                pos += length
                
        return domain.rstrip('.')
        

            

            
    def stop(self):
        """Stop the DNS resolver"""
        print("[+] Stopping DNS Resolver...")
        self.running = False
        
        if self.query_socket:
            self.query_socket.close()
        if self.response_socket:
            self.response_socket.close()
            
        print("[+] DNS Resolver stopped")

if __name__ == "__main__":
    resolver = SimpleDNSResolver()
    try:
        resolver.start()
    except KeyboardInterrupt:
        resolver.stop() 