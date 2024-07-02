from log_utils import *

def main():
    log_file_path = get_file_path_from_cmd_line(1)
    
    # Generate destination port reports
    port_tally = tally_port_traffic(log_file_path)
    for port, count in port_tally.items():
        if count >= 100:
            generate_port_report(log_file_path, port)
    
    # Generate invalid user report
    generate_invalid_user_report(log_file_path)
    
    # Extract source IP records
    extract_source_ip_records(log_file_path, '220.195.35.40')

if __name__ == "__main__":
    main()