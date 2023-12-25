import ipaddress
from datetime import datetime
import pandas as pd
from pathlib import Path
from f5.bigip import ManagementRoot

# Define the F5 device hosts and data groups
f5_hosts = ['192.168.0.200']
data_groups = ['Blacklist', 'blacklist2']

def is_valid_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private:
            return False
        excluded_subnets = [
            ipaddress.ip_network('185.180.44.0/24'),
            ipaddress.ip_network('185.180.45.0/24')
        ]
        for subnet in excluded_subnets:
            if ip in subnet:
                return False
        return True
    except ValueError:
        return False

def authenticate_to_f5(username, password, host):
    try:
        bigip = ManagementRoot(host, username, password)
        return bigip
    except Exception as e:
        return None

def check_and_add_ip_to_f5(ip_str, username, password, already_added_ips, ips_added_to_f5):
    formatted_ip = ip_str if '/' in ip_str else ip_str + '/32'
    actions = []

    for host in f5_hosts:
        bigip = authenticate_to_f5(username, password, host)
        if not bigip:
            continue

        for data_group in data_groups:
            data_group_obj = bigip.tm.ltm.data_group.internals.internal.load(name=data_group)
            current_records = [record['name'] for record in data_group_obj.records]

            if formatted_ip in current_records:
                actions.append(f"Skipped {formatted_ip} in {data_group} of {host} (already exists)")
            else:
                data_group_obj.records.append({'name': formatted_ip, 'data': ''})
                data_group_obj.update()
                ips_added_to_f5.append(formatted_ip)
                actions.append(f"Added {formatted_ip} in {data_group} of {host}")

    return actions

def add2xl(ip_str, cr_number, username, ips_added_to_excel):
    excel_path = Path('adminData/ipblock/ipdetails.xlsx')
    new_data = {'IP address': [ip_str], 'CR Number': [cr_number], 'Date Added': [datetime.now().strftime("%Y-%m-%d %H:%M:%S")], 'Username': [username]}

    if excel_path.is_file():
        df = pd.read_excel(excel_path)
        if ip_str not in df['IP address'].values:
            df = pd.concat([df, pd.DataFrame(new_data)], ignore_index=True)
            with pd.ExcelWriter(excel_path, mode='w', engine='openpyxl') as writer:
                df.to_excel(writer, index=False)
            ips_added_to_excel.append(ip_str)
    else:
        df = pd.DataFrame(new_data)
        with pd.ExcelWriter(excel_path, mode='w', engine='openpyxl') as writer:
            df.to_excel(writer, index=False)
        ips_added_to_excel.append(ip_str)

def getdataStart(ip_str, cr_number, username, password, invalid_ips, already_added_ips, ips_added_to_f5, ips_added_to_excel):
    if is_valid_ip(ip_str):
        messages = check_and_add_ip_to_f5(ip_str, username, password, already_added_ips, ips_added_to_f5)
        if ip_str not in already_added_ips:
            add2xl(ip_str, cr_number, username, ips_added_to_excel)
        return messages
    else:
        invalid_ips.append(ip_str)
        return [f"Invalid IP: {ip_str}"]

def print_results(invalid_ips, already_added_ips, ips_added_to_f5, ips_added_to_excel):
    print("Invalid IPs:", invalid_ips)
    print("Already added IPs to F5:", already_added_ips)
    print("IPs added to the F5 device:", ips_added_to_f5)
    print("IPs added to Excel:", ips_added_to_excel)

if __name__ == '__main__':
    user_id = 'admin'
    password = 'J@mb0rd@123&&'
    cr_number = 'CR123456'
    ip_list = ['192.168.1.1', '10.0.0.1', '185.180.44.1','100.22.33.44', '14.0.0.10']

    invalid_ips = []
    already_added_ips = []
    ips_added_to_f5 = []
    ips_added_to_excel = []

    action_messages = []
    for ip_str in ip_list:
        messages = getdataStart(ip_str, cr_number, user_id, password, invalid_ips, already_added_ips, ips_added_to_f5, ips_added_to_excel)
        action_messages.extend(messages)

    with open('log.txt', 'w') as log_file:
        log_file.write("IPs added:\n")
        for message in action_messages:
            if "Added" in message:
                log_file.write(message + "\n")

        log_file.write("\nInvalid IPs:\n")
        for ip in invalid_ips:
            log_file.write(ip + "\n")

        log_file.write("\nAlready present:\n")
        for message in action_messages:
            if "Skipped" in message:
                log_file.write(message + "\n")

        log_file.write("\nIPs added to Excel:\n")
        for ip in ips_added_to_excel:
            log_file.write(ip + "\n")
