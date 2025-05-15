#!/usr/bin/env python3
import os
import argparse

# --- Configuration ---
DEFAULT_SORTED_OUTPUT_FILE = "sorted_ip_addresses.txt"

# --- Functions ---

def binary_to_decimal_ip(binary_ip_str):
    """
    Converts an IP address from binary dot-notation to decimal dot-notation.
    Assumes each part of binary_ip_str is an 8-digit binary octet.

    Args:
        binary_ip_str (str): The IP address in binary format, where each octet
                             is expected to be 8 digits (e.g., "11000000.10101000.00000001.00000001").
    Returns:
        str: The IP address in decimal format (e.g., "192.168.1.1").
             Returns None if conversion fails or format is invalid.
    """
    try:
        octets = binary_ip_str.strip().split('.')
        # This function is now called only if we've already determined it *should* be binary
        # based on the 4x8-digit rule, so len(octets) should be 4.
        # The primary validation was done before calling this.
        if len(octets) != 4: # Still a good safeguard
            return None
            
        decimal_octets = []
        for octet_str in octets:
            # The caller should ensure octet_str is 8 digits and binary.
            # This function just performs the conversion.
            if not (len(octet_str) == 8 and all(c in '01' for c in octet_str)):
                 # This condition implies the caller didn't adhere to the new rule,
                 # or there's a logic error in the caller.
                 # print(f"Debug: binary_to_decimal_ip called with malformed octet: {octet_str}")
                 return None
            dec_val = int(octet_str, 2)
            # int(octet_str, 2) for an 8-char binary string will always be 0-255.
            decimal_octets.append(str(dec_val))
        return ".".join(decimal_octets)
    except ValueError: # Should be rare if pre-checks are done
        return None

def sort_key_for_ip(ip_address_str):
    """
    Creates a sort key for a decimal IP address string.
    IP addresses are converted to a tuple of integers for correct numerical sorting.
    Args:
        ip_address_str (str): The IP address string (e.g., "192.168.1.1").
    Returns:
        tuple: A tuple of integers representing the IP address (e.g., (192, 168, 1, 1)).
               Returns None if the IP address format is invalid.
    """
    try:
        parts = list(map(int, ip_address_str.strip().split(".")))
        if len(parts) == 4 and all(0 <= part <= 255 for part in parts):
            return tuple(parts)
        return None
    except ValueError:
        return None

def load_and_process_ips_from_file(filepath):
    """
    Loads IP addresses from a single file.
    If all four octets of an IP string are exactly 8 digits and purely binary,
    it's treated as binary. Otherwise, it's treated as decimal.
    Converts binary to decimal, and validates all IPs.
    Args:
        filepath (str): The path to the file containing IP addresses.
    Returns:
        list: A list of valid decimal IP address strings.
    """
    processed_decimal_ips = []
    if not filepath:
        return processed_decimal_ips

    try:
        with open(filepath, "r") as f:
            for line_num, line in enumerate(f, 1):
                ip_str_original = line.strip()
                if not ip_str_original: # Skip empty lines
                    continue

                octets = ip_str_original.split('.')
                is_strict_binary_format = False

                if len(octets) == 4:
                    is_strict_binary_format = True # Assume true initially
                    for octet_str in octets:
                        if not (len(octet_str) == 8 and all(c in '01' for c in octet_str)):
                            is_strict_binary_format = False
                            break # Not all octets meet the strict binary criteria

                final_decimal_ip = None

                if is_strict_binary_format:
                    # print(f"Debug: Line {line_num} '{ip_str_original}' attempting as STRICT BINARY.") # Optional
                    converted_ip = binary_to_decimal_ip(ip_str_original)
                    if converted_ip and sort_key_for_ip(converted_ip): # Ensure converted is also a valid decimal IP
                        final_decimal_ip = converted_ip
                    else:
                        print(f"Warning: Line {line_num}: Strict binary IP '{ip_str_original}' failed conversion or resulted in invalid decimal. Skipping.")
                else:
                    # print(f"Debug: Line {line_num} '{ip_str_original}' attempting as DECIMAL.") # Optional
                    if sort_key_for_ip(ip_str_original):
                        final_decimal_ip = ip_str_original
                    else:
                        print(f"Warning: Line {line_num}: Invalid decimal IP format: '{ip_str_original}'. Skipping.")
                
                if final_decimal_ip:
                    processed_decimal_ips.append(final_decimal_ip)
                
    except FileNotFoundError:
        print(f"Error: Input file not found at '{filepath}'.")
    except Exception as e:
        print(f"Error reading file '{filepath}': {e}")
    return processed_decimal_ips

def save_ips_to_file(filepath, ip_list):
    """
    Saves a list of IP addresses to a file, one IP per line.
    Args:
        filepath (str): The path to the file where IPs will be saved.
        ip_list (list): A list of IP address strings.
    """
    try:
        with open(filepath, "w") as f:
            for ip in ip_list:
                f.write(ip + "\n")
        print(f"Sorted IP addresses saved to '{filepath}'")
    except Exception as e:
        print(f"Error writing to file '{filepath}': {e}")

# --- Main Logic ---
def main():
    parser = argparse.ArgumentParser(description="Load IP addresses from a single file (auto-detecting 8-digit/octet binary vs decimal), sort, and save.")
    parser.add_argument("input_file",
                        help="Path to the file containing IP addresses (one per line).")
    parser.add_argument("-o", "--output-file",
                        help="Path to the file where sorted IP addresses will be saved.",
                        default=DEFAULT_SORTED_OUTPUT_FILE)
    
    args = parser.parse_args()

    print(f"Processing input file: '{args.input_file}'")
    all_decimal_ips = load_and_process_ips_from_file(args.input_file)
    
    unique_valid_ips = []
    seen_ips_for_dedup = set()
    for ip_str in all_decimal_ips:
        if ip_str not in seen_ips_for_dedup:
            unique_valid_ips.append(ip_str)
            seen_ips_for_dedup.add(ip_str)

    if unique_valid_ips:
        print("Sorting IP addresses...")
        unique_valid_ips.sort(key=lambda ip: sort_key_for_ip(ip) or (0,0,0,0))
        save_ips_to_file(args.output_file, unique_valid_ips)
        print(f"Processed and saved {len(unique_valid_ips)} unique valid IP addresses.")
    else:
        print("No valid IP addresses found to process from the input file.")

if __name__ == "__main__":
    main()