# app/utils/network_utils.py - Complete implementation
"""
Network Utilities
Helper functions for IP validation and network operations
"""

import ipaddress
import socket
from typing import Optional, List, Dict, Any

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
        network_addr = ipaddress.ip_network(network, strict=False)
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

def validate_port(port: int) -> bool:
    """Validate network port number"""
    return 1 <= port <= 65535

def normalize_ip(ip: str) -> Optional[str]:
    """Normalize IP address format"""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None

def get_network_info(ip: str, network: str) -> Dict[str, Any]:
    """Get network information for IP"""
    try:
        ip_addr = ipaddress.ip_address(ip)
        network_addr = ipaddress.ip_network(network, strict=False)
        
        return {
            'ip': str(ip_addr),
            'network': str(network_addr),
            'is_in_network': ip_addr in network_addr,
            'is_private': ip_addr.is_private,
            'is_loopback': ip_addr.is_loopback,
            'is_multicast': ip_addr.is_multicast
        }
    except ValueError:
        return {}

def get_cidr_from_netmask(netmask: str) -> Optional[int]:
    """Convert netmask to CIDR notation"""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask}", strict=False).prefixlen
    except ValueError:
        return None