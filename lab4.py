import sys
import os
import re

def get_log_file_path(param_num):
    if len(sys.argv) <= param_num:
        print(f"Error: Missing log file path as command line parameter {param_num}")
        sys.exit(1)
    
    log_file_path = sys.argv[param_num]
    if not os.path.isfile(log_file_path):
        print(f"Error: {log_file_path} is not a valid file path")
        sys.exit(1)
    
    return log_file_path

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

def main():
    log_file_path = get_log_file_path(1)
    
    # Example usage of filter_log_by_regex function
    filter_log_by_regex(log_file_path, 'sshd', case_sensitive=False)
    filter_log_by_regex(log_file_path, 'invalid user', case_sensitive=False)
    filter_log_by_regex(log_file_path, 'invalid user.*220.195.35.40', case_sensitive=False)
    filter_log_by_regex(log_file_path, 'error', case_sensitive=False)
    filter_log_by_regex(log_file_path, 'pam', case_sensitive=False)

if __name__ == "__main__":
    main()