################################################################################
# COMS3200 Assignment 2
# Python 3 DNS Requester
# Shared helpers and constants
################################################################################

from ipaddress import ip_address

# DNS Request types
# IPv4 = 'A', IPv6 = 'AAAA', Mail Serv = 'MX', Reserve lookup = 'PTR'
QUERY_TYPES = {
    0: "A",
    1: "AAAA",
    2: "MX",
    3: "PTR"
}

# Default UDP Port to DNS Server
PORT = 53

# Default DNS Server target
DNS_DEF = '8.8.8.8'

# Line break for formatting
LINE_BREAK = "=" * 20


def is_ip(address):
    """
    Checks if input is an IP address using the ipaddress module.
    Args:
        address (str): The string to check, e.g., "127.0.0.1", "google.com"

    Returns:
        bool: True if a valid IPv4 or IPv6 address, else false.

    """
    try:
        ip_address(address)
    except ValueError:
        return False
    return True
