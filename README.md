# IP Address Processor Tool

A command-line utility written in Python to process, sort, and validate IP addresses from a given input file. The tool automatically distinguishes between decimal IP addresses and binary IP addresses (where each of the four octets is exactly 8 digits long and contains only '0's and '1's).

## Features

* Accepts a single input file containing a list of IP addresses (one per line).
* Automatically detects if an IP string is a potential 8-digit-octet binary format or a decimal format.
* Converts valid binary IPs (strictly 4 octets, each 8-digits of '0's or '1's) to their decimal representation.
* Validates IP address formats and octet ranges (0-255) for both original decimal IPs and converted binary IPs.
* Sorts all unique valid IP addresses numerically.
* Saves the sorted, unique, valid IP addresses to an output file.
* Provides warnings for malformed, unparsable, or invalid IP strings.
* Command-line interface for specifying input and output files.

## Requirements

* Python 3.x (no external libraries needed beyond the standard library)

## Installation / Setup

1.  Clone this repository:
    ```bash
    git clone https://github.com/bozinfosec/ip-processor-tool.git
    cd ip-processor-tool # e.g., ip_processor_tool
    ```
2.  (Optional, but good practice for development) Create and activate a virtual environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Linux/macOS
    # venv\Scripts\activate  # On Windows
    ```
3.  The script `ip_processor.py` is ready to be used directly.

## Usage

Ensure the script is executable (on Linux/macOS):
```bash
chmod +x ip_processor.py
