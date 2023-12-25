from f5.bigip import ManagementRoot
import ipaddress

# Configuration for F5 BIG-IP hosts
# hosts = ['192.168.0.200', '192.168.0.201']
hosts = ['192.168.0.200']

# Function to check if the IP is valid and not in the excluded subnets
def is_valid_ip(ip_str):
    try:
        ip = ipaddress.ip_interface(ip_str)
    except ValueError:
        return False

    if ip.ip.is_private:
        return False

    excluded_subnets = [ipaddress.ip_network('185.180.44.0/24'), ipaddress.ip_network('185.180.45.0/24')]
    for subnet in excluded_subnets:
        if ip.ip in subnet:
            return False

    return True

# Function to add IPs to data groups in the F5 BIG-IP
def add_ips_to_datagroup(bigip, ips, existing_ips, added_ips):
    data_groups = ['Blacklist', 'blacklist2']

    for datagroup_name in data_groups:
        if not bigip.tm.ltm.data_group.internals.internal.exists(name=datagroup_name):
            print(f"Data group {datagroup_name} does not exist on {bigip._meta_data['uri']}. Skipping...")
            continue

        data_group = bigip.tm.ltm.data_group.internals.internal.load(name=datagroup_name)
        current_records = data_group.records

        for ip in ips:
            if '/' not in ip:
                ip += '/32'

            if any(record['name'] == ip for record in current_records):
                existing_ips.add(ip)
            else:
                current_records.append({'name': ip, 'data': ''})
                added_ips.add(ip)

        data_group.update(records=current_records)

# Function to authenticate to the F5 BIG-IP
def authenticate(username, password, host):
    try:
        bigip = ManagementRoot(host, username, password)
        bigip.tm.ltm.data_group.internals.get_collection()
        return bigip
    except Exception as e:
        print(f"Error connecting to {host}: {e}")
        return None

# Main function to handle user interactions
def main():
    user_id = input("Enter your ID: ")
    user_password = input("Enter your password: ")

    connected_bigips = []
    invalid_ips = set()
    existing_ips = set()
    added_ips = set()

    # Authenticate and connect to the BIG-IP hosts
    for host in hosts:
        bigip = authenticate(user_id, user_password, host)
        if bigip:
            connected_bigips.append(bigip)
        else:
            print(f"{host} not reachable or authentication failed.")

    # Exit if no BIG-IP devices are accessible
    if not connected_bigips:
        print("None of the F5 devices are accessible. Exiting.")
        return

    # User input loop
    while True:
        ip_input = input("Enter IP (or type 'exit' to finish): ")
        if ip_input.strip().lower() == 'exit':
            break

        # Validate and add IP
        if is_valid_ip(ip_input):
            ips = [ip_input.strip()]
            for bigip in connected_bigips:
                add_ips_to_datagroup(bigip, ips, existing_ips, added_ips)
        else:
            invalid_ips.add(ip_input.strip())
            print(f"IP {ip_input} is invalid and was not added.")

    # Print the summaries
    print("\nSummary:")
    print(f"Invalid IP (cannot add these IP addresses): {', '.join(sorted(invalid_ips))}")
    print(f"Already exist: {', '.join(sorted(existing_ips))}")
    print(f"IPs Added successfully: {', '.join(sorted(added_ips))}")

# Entry point of the script
if __name__ == '__main__':
    main()
