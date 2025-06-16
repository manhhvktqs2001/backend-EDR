"""
Network Utilities
Helper functions for IP validation and network operations
"""

import ipaddress
import socket
from typing import Optional, List

def validate_ip_address(ip: str) -> bool:
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_internal_ip(ip: str, network: str = '192.168.20.0/24') -> bool:
    """Check if IP is within internal network range"""
    try:
        ip_addr = ipaddress.ip_address(ip)
        network_addr = ipaddress.ip_network(network)
        return ip_addr in network_addr
    except ValueError:
        return False

def is_private_ip(ip: str) -> bool:
    """Check if IP is private (RFC 1918)"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def get_hostname_from_ip(ip: str) -> Optional[str]:
    """Get hostname from IP address"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return None