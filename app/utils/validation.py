# app/utils/validation.py
"""
Data Validation Utilities
Helper functions for validating inputs and data
"""

import re
import ipaddress
import uuid
from typing import Any, List, Dict, Optional, Tuple

def validate_hostname(hostname: str) -> bool:
    """Validate hostname format"""
    if not hostname or len(hostname) > 255:
        return False
    
    # Hostname regex pattern
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, hostname))

def validate_mac_address(mac: str) -> bool:
    """Validate MAC address format"""
    if not mac:
        return False
    
    # MAC address patterns
    patterns = [
        r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',  # XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
        r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$'     # XXXX.XXXX.XXXX
    ]
    
    return any(re.match(pattern, mac) for pattern in patterns)

def validate_hash(hash_value: str, hash_type: str = 'any') -> bool:
    """Validate hash format (MD5, SHA1, SHA256)"""
    if not hash_value:
        return False
    
    hash_patterns = {
        'md5': r'^[a-fA-F0-9]{32}$',
        'sha1': r'^[a-fA-F0-9]{40}$',
        'sha256': r'^[a-fA-F0-9]{64}$'
    }
    
    if hash_type == 'any':
        return any(re.match(pattern, hash_value) for pattern in hash_patterns.values())
    
    pattern = hash_patterns.get(hash_type.lower())
    return bool(pattern and re.match(pattern, hash_value))

def validate_port(port: int) -> bool:
    """Validate network port number"""
    return 1 <= port <= 65535

def validate_severity(severity: str) -> bool:
    """Validate alert/event severity"""
    valid_severities = ['Info', 'Low', 'Medium', 'High', 'Critical']
    return severity in valid_severities

def validate_event_type(event_type: str) -> bool:
    """Validate event type"""
    valid_types = ['Process', 'File', 'Network', 'Registry', 'Authentication', 'System']
    return event_type in valid_types

def sanitize_string(value: str, max_length: int = 255) -> str:
    """Sanitize string input"""
    if not isinstance(value, str):
        return str(value)[:max_length]
    
    # Remove null bytes and control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
    return sanitized[:max_length].strip()

def validate_json_structure(data: Dict, required_fields: List[str]) -> Tuple[bool, str]:
    """Validate JSON structure has required fields"""
    if not isinstance(data, dict):
        return False, "Data must be a dictionary"
    
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return False, f"Missing required fields: {missing_fields}"
    
    return True, "Valid"

def validate_agent_id(agent_id: str) -> bool:
    """Validate agent ID format (UUID)"""
    try:
        uuid.UUID(agent_id)
        return True
    except ValueError:
        return False

def validate_file_path(file_path: str) -> bool:
    """Validate file path format"""
    if not file_path:
        return False
    
    # Basic file path validation
    # Reject paths with null bytes or dangerous patterns
    dangerous_patterns = ['\x00', '..', '<', '>', '|']
    return not any(pattern in file_path for pattern in dangerous_patterns)

def validate_command_line(command_line: str) -> bool:
    """Validate command line format"""
    if not command_line:
        return True  # Empty command line is valid
    
    # Basic validation - reject null bytes
    return '\x00' not in command_line

def validate_registry_key(registry_key: str) -> bool:
    """Validate Windows registry key format"""
    if not registry_key:
        return False
    
    # Basic registry key validation
    valid_roots = [
        'HKEY_CLASSES_ROOT', 'HKCR',
        'HKEY_CURRENT_USER', 'HKCU',
        'HKEY_LOCAL_MACHINE', 'HKLM',
        'HKEY_USERS', 'HKU',
        'HKEY_CURRENT_CONFIG', 'HKCC'
    ]
    
    # Check if starts with valid root
    return any(registry_key.upper().startswith(root) for root in valid_roots)