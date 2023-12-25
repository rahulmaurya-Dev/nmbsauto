from f5.bigip import ManagementRoot
import ipaddress

hosts = ['192.168.0.200', '192.168.0.201']

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

def add_ips_to_datagroup(bigip, ips):
    data_groups = ['Blacklist', 'Blacklist2']

    for datagroup_name in data_groups:
        if not bigip.tm.ltm.data_group.internals.internal.exists(name=datagroup_name):
            print(f"Data group {datagroup_name} does not exist on {bigip._meta_data['uri']}. Skipping...")
            continue

        data_group = bigip.tm.ltm.data_group.internals.internal.load(name=datagroup_name)
        current_records = data_group.raw['records']

        for ip in ips:
            if '/' not in ip:
                ip += '/32'

            if not any(record['name'] == ip for record in current_records):
                current_records.append({'name': ip, 'data': ''})

        data_group.modify(records=current_records)

def authenticate(username, password, host):
    try:
        bigip = ManagementRoot(host, username, password)
        bigip.tm.ltm.data_group.internals.get_collection()
        return bigip
    except:
        return None

def main():
    user_id = input("Enter your ID: ")
    user_password = input("Enter your password: ")

    connected_bigips = []

    for host in hosts:
        bigip = authenticate(user_id, user_password, host)
        if bigip:
            connected_bigips.append(bigip)
        else:
            print(f"{host} not reachable or authentication failed.")

    if len(connected_bigips) == len(hosts):
        print("All F5 devices are accessible.")
    elif not connected_bigips:
        print("None of the F5 devices are accessible. Exiting.")
        return

    while True:
        ip_input = input("Enter IP (or type 'exit' to finish): ")
        
        if ip_input.strip().lower() == 'exit':
            break
        
        if is_valid_ip(ip_input):
            ips = [ip_input.strip()]
            for bigip in connected_bigips:
                add_ips_to_datagroup(bigip, ips)
                print(f"IP {ip_input} added successfully to the data groups on {bigip._meta_data['uri']}!")
        else:
            print(f"IP {ip_input} is invalid and was not added.")

if __name__ == '__main__':
    main()
