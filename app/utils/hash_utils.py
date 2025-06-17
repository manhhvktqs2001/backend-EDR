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

def validate_hash(data: bytes, expected_hash: str, algorithm: str = 'sha256') -> bool:
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

def normalize_hash(hash_value: str) -> str:
    """Normalize hash to lowercase"""
    return hash_value.lower().strip() if hash_value else ""

def detect_hash_type(hash_value: str) -> Optional[str]:
    """Detect hash type based on length"""
    if not hash_value:
        return None
    
    clean_hash = normalize_hash(hash_value)
    length = len(clean_hash)
    
    if length == 32:
        return 'md5'
    elif length == 40:
        return 'sha1'
    elif length == 64:
        return 'sha256'
    else:
        return None