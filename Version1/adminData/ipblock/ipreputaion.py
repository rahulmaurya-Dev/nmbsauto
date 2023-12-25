import requests
import itertools
import time


# List your VirusTotal API Keys here
api_keys = itertools.cycle([
'3df10bfdee3c3b307d068220e0034a9848b2ee0f738efeaa8a3d68821da7eafd',
'6470c66dfc247f33fa453cb24c36ee8e4ba84e2270ab32be381638807eaf65ea',
'ea7a6852d49a6fd5e083d2202bf849d943537623e5650df0f2ec9d1e72a6da3f',
'36f4481b9c405b255a6af45bedee838e286990690a2dae5c8749a47478b13036',
'9934baa6f3b99390768ba5a6dd4d35882e6c1ca1cba480ab4333b65e11e0079b',
'74a99149fc8e7fa7db9d3401801a74d1156801a5ae294ee2e9898b4959f510d9',
'c97a3f495156f9a9efdb363ae3bf7134d33883d65de10486cf41dfb4196659a7'
    # Add more keys if available
])

# List of IP addresses to check
ip_addresses = [
    "103.159.47.34", "138.121.113.182", "103.142.21.197", "212.120.170.90",
    "190.122.185.170", "212.95.180.50", "103.93.93.118", "94.75.76.3",
    "103.180.194.146", "200.215.250.186", "179.48.11.6", "36.94.185.122",
    "77.46.138.38", "177.234.196.21", "111.225.153.236", "103.143.63.33",
    "84.204.40.154", "66.27.58.70", "52.101.68.18", "103.226.141.16"
]

# Function to check the reputation of an IP address
def check_ip_reputation(ip, api_key):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        # Flag as bad if malicious is greater than 0
        return stats['malicious'] > 0
    else:
        return False

# Function to check IPs and return those with a bad reputation
# Function to check IPs and return those with good and bad reputations
def get_ips_with_reputations(ip_addresses):
    good_ips = []
    bad_ips = []
    for ip in ip_addresses:
        api_key = next(api_keys)  # Get the next API key from the cycle
        if check_ip_reputation(ip, api_key):
            bad_ips.append(ip)
        else:
            good_ips.append(ip)
        time.sleep(3)  # Wait for 3 seconds between requests
    return good_ips, bad_ips

# Find and print IPs with good and bad reputations
# good_reputation_ips, bad_reputation_ips = get_ips_with_reputations(ip_addresses)
# print("IPs with good reputation:", good_reputation_ips)
# print("IPs with bad reputation:", bad_reputation_ips)
# print("Number of IPs with good reputation:", len(good_reputation_ips))
# print("Number of IPs with bad reputation:", len(bad_reputation_ips))