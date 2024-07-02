import sys
import os
import re
import csv

def get_file_path_from_cmd_line(param_num):
    if len(sys.argv) <= param_num:
        print(f"Error: Missing file path as command line parameter {param_num}")
        sys.exit(1)
    
    file_path = sys.argv[param_num]
    if not os.path.isfile(file_path):
        print(f"Error: {file_path} is not a valid file path")
        sys.exit(1)
    
    return file_path

def filter_log_by_regex(log_file_path, regex, case_sensitive=True, print_records=True, print_summary=True):
    matching_records = []
    flags = 0 if case_sensitive else re.IGNORECASE

    with open(log_file_path, 'r') as file:
        for line in file:
            if re.search(regex, line, flags):
                matching_records.append(line.strip())
                if print_records:
                    print(line.strip())
    
    if print_summary:
        sensitivity = "case-sensitive" if case_sensitive else "case-insensitive"
        print(f"\nThe log file contains {len(matching_records)} records that {sensitivity} match the regex \"{regex}\".")
    
    return matching_records

def filter_log_by_regex(log_file_path, regex, case_sensitive=True, print_records=True, print_summary=True):
    matching_records = []
    extracted_data = []
    flags = 0 if case_sensitive else re.IGNORECASE

    with open(log_file_path, 'r') as file:
        for line in file:
            match = re.search(regex, line, flags)
            if match:
                matching_records.append(line.strip())
                if match.groups():
                    extracted_data.append(match.groups())
                if print_records:
                    print(line.strip())
    
    if print_summary:
        sensitivity = "case-sensitive" if case_sensitive else "case-insensitive"
        print(f"\nThe log file contains {len(matching_records)} records that {sensitivity} match the regex \"{regex}\".")
    
    return matching_records, extracted_data

def tally_port_traffic(log_file_path):
    port_tally = {}
    regex = r'DPT=(\d+)'
    
    with open(log_file_path, 'r') as file:
        for line in file:
            match = re.search(regex, line)
            if match:
                port = match.group(1)
                port_tally[port] = port_tally.get(port, 0) + 1
    
    return port_tally

def generate_port_report(log_file_path, port_number):
    regex = r'(\w+\s+\d+\s+\d+:\d+:\d+).*SRC=([\d.]+).*DST=([\d.]+).*SPT=(\d+).*DPT=(\d+)'
    matching_records, extracted_data = filter_log_by_regex(log_file_path, regex, print_records=False, print_summary=False)
    
    filename = f'destination_port_{port_number}_report.csv'
    with open(filename, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['Date', 'Time', 'Source IP', 'Destination IP', 'Source Port', 'Destination Port'])
        for record in extracted_data:
            date_time = record[0].split()
            if len(date_time) >= 2 and record[4] == port_number:
                csvwriter.writerow([date_time[0], date_time[1], record[1], record[2], record[3], record[4]])
    
    print(f"Report for port {port_number} saved as {filename}")

def generate_invalid_user_report(log_file_path):
    regex = r'(\w+\s+\d+\s+\d+:\d+:\d+).*Invalid user (\w+) from ([\d.]+)'
    matching_records, extracted_data = filter_log_by_regex(log_file_path, regex, print_records=False, print_summary=False)
    
    filename = 'invalid_users.csv'
    with open(filename, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['Date', 'Time', 'Username', 'IP Address'])
        for record in extracted_data:
            date_time = record[0].split()
            if len(date_time) >= 2:
                csvwriter.writerow([date_time[0], date_time[1], record[1], record[2]])
    
    print(f"Invalid user report saved as {filename}")

def extract_source_ip_records(log_file_path, source_ip):
    regex = rf'.*SRC={source_ip}.*'
    matching_records, _ = filter_log_by_regex(log_file_path, regex, print_records=False, print_summary=False)
    
    filename = f'source_ip_{source_ip.replace(".", "_")}.log'
    with open(filename, 'w') as file:
        for record in matching_records:
            file.write(f"{record}\n")
    
    print(f"Source IP records saved as {filename}")