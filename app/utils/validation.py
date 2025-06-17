# app/utils/validation.py
"""
Data Validation Utilities
Helper functions for validating inputs and data
"""

import re
import ipaddress
from typing import Any, List, Dict, Optional

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
    valid_severities = ['Low', 'Medium', 'High', 'Critical']
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

def validate_json_structure(data: Dict, required_fields: List[str]) -> tuple[bool, str]:
    """Validate JSON structure has required fields"""
    if not isinstance(data, dict):
        return False, "Data must be a dictionary"
    
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return False, f"Missing required fields: {missing_fields}"
    
    return True, "Valid"

# app/utils/hash_utils.py
"""
Hash Calculation Utilities
Helper functions for file hashing and hash operations
"""

import hashlib
import hmac
from typing import Optional

def calculate_md5(data: bytes) -> str:
    """Calculate MD5 hash of data"""
    return hashlib.md5(data).hexdigest()

def calculate_sha1(data: bytes) -> str:
    """Calculate SHA1 hash of data"""
    return hashlib.sha1(data).hexdigest()

def calculate_sha256(data: bytes) -> str:
    """Calculate SHA256 hash of data"""
    return hashlib.sha256(data).hexdigest()

def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """Calculate hash of file"""
    try:
        hash_func = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256
        }.get(algorithm.lower())
        
        if not hash_func:
            return None
        
        hasher = hash_func()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    except Exception:
        return None

def verify_hash(data: bytes, expected_hash: str, algorithm: str = 'sha256') -> bool:
    """Verify data against expected hash"""
    hash_functions = {
        'md5': calculate_md5,
        'sha1': calculate_sha1,
        'sha256': calculate_sha256
    }
    
    hash_func = hash_functions.get(algorithm.lower())
    if not hash_func:
        return False
    
    calculated_hash = hash_func(data)
    return hmac.compare_digest(calculated_hash.lower(), expected_hash.lower())

# app/utils/datetime_utils.py
"""
DateTime Utilities
Helper functions for datetime operations and formatting
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, Union
import time

def get_current_timestamp() -> float:
    """Get current Unix timestamp"""
    return time.time()

def get_current_datetime() -> datetime:
    """Get current datetime with timezone"""
    return datetime.now(timezone.utc)

def format_datetime(dt: datetime, format_string: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format datetime to string"""
    return dt.strftime(format_string)

def parse_datetime(date_string: str, format_string: str = "%Y-%m-%d %H:%M:%S") -> Optional[datetime]:
    """Parse string to datetime"""
    try:
        return datetime.strptime(date_string, format_string)
    except ValueError:
        return None

def datetime_to_iso(dt: datetime) -> str:
    """Convert datetime to ISO format string"""
    return dt.isoformat()

def iso_to_datetime(iso_string: str) -> Optional[datetime]:
    """Convert ISO format string to datetime"""
    try:
        return datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
    except ValueError:
        return None

def get_time_ago(dt: datetime) -> str:
    """Get human-readable time ago string"""
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    diff = now - dt
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return f"{int(seconds)} seconds ago"
    elif seconds < 3600:
        return f"{int(seconds // 60)} minutes ago"
    elif seconds < 86400:
        return f"{int(seconds // 3600)} hours ago"
    else:
        return f"{int(seconds // 86400)} days ago"

def is_within_time_range(dt: datetime, hours: int) -> bool:
    """Check if datetime is within specified hours from now"""
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    time_diff = now - dt
    return time_diff <= timedelta(hours=hours)

# app/utils/json_utils.py
"""
JSON Utilities
Helper functions for JSON operations and validation
"""

import json
from typing import Any, Dict, Optional, Union
import logging

logger = logging.getLogger(__name__)

def safe_json_loads(json_string: str) -> Optional[Dict]:
    """Safely parse JSON string"""
    try:
        return json.loads(json_string)
    except (json.JSONDecodeError, TypeError) as e:
        logger.warning(f"Failed to parse JSON: {e}")
        return None

def safe_json_dumps(data: Any, indent: Optional[int] = None) -> Optional[str]:
    """Safely serialize data to JSON"""
    try:
        return json.dumps(data, indent=indent, default=str, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        logger.warning(f"Failed to serialize JSON: {e}")
        return None

def merge_json_objects(obj1: Dict, obj2: Dict) -> Dict:
    """Merge two JSON objects"""
    result = obj1.copy()
    result.update(obj2)
    return result

def extract_json_field(data: Dict, field_path: str, default: Any = None) -> Any:
    """Extract field from nested JSON using dot notation"""
    try:
        fields = field_path.split('.')
        result = data
        for field in fields:
            result = result[field]
        return result
    except (KeyError, TypeError):
        return default

def validate_json_schema(data: Dict, schema: Dict) -> tuple[bool, str]:
    """Basic JSON schema validation"""
    try:
        for field, field_type in schema.items():
            if field not in data:
                return False, f"Missing required field: {field}"
            
            if not isinstance(data[field], field_type):
                return False, f"Field {field} must be of type {field_type.__name__}"
        
        return True, "Valid"
    except Exception as e:
        return False, f"Validation error: {str(e)}"

# app/utils/formatting.py
"""
Data Formatting Utilities
Helper functions for formatting and converting data
"""

def format_bytes(bytes_value: int) -> str:
    """Format bytes to human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"

def format_percentage(value: float, decimal_places: int = 1) -> str:
    """Format decimal as percentage"""
    return f"{value:.{decimal_places}f}%"

def format_duration(seconds: int) -> str:
    """Format seconds to human readable duration"""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m {seconds % 60}s"
    elif seconds < 86400:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"{days}d {hours}h"

def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate string to specified length"""
    if len(text) <= max_length:
        return text
    return text[:max_length - len(suffix)] + suffix

def normalize_string(text: str) -> str:
    """Normalize string (lowercase, strip, etc.)"""
    return text.strip().lower() if text else ""

def format_list_as_string(items: list, separator: str = ", ") -> str:
    """Format list as comma-separated string"""
    return separator.join(str(item) for item in items)