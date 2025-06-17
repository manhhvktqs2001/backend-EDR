# app/utils/json_utils.py
"""
JSON Utilities
Helper functions for JSON operations and validation
"""

import json
import logging
from typing import Any, Dict, Optional, Union

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

def flatten_json(data: Dict, separator: str = '.') -> Dict:
    """Flatten nested JSON object"""
    def _flatten(obj, parent_key='', sep='.'):
        items = []
        for k, v in obj.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(_flatten(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)
    
    return _flatten(data, sep=separator)

def unflatten_json(data: Dict, separator: str = '.') -> Dict:
    """Unflatten JSON object"""
    result = {}
    for key, value in data.items():
        keys = key.split(separator)
        d = result
        for k in keys[:-1]:
            if k not in d:
                d[k] = {}
            d = d[k]
        d[keys[-1]] = value
    return result