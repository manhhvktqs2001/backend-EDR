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

def camel_to_snake(name: str) -> str:
    """Convert camelCase to snake_case"""
    import re
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def snake_to_camel(name: str) -> str:
    """Convert snake_case to camelCase"""
    components = name.split('_')
    return components[0] + ''.join(x.title() for x in components[1:])

def format_number(number: float, decimal_places: int = 2) -> str:
    """Format number with specified decimal places"""
    return f"{number:.{decimal_places}f}"

def format_file_size(size_bytes: int) -> str:
    """Format file size in bytes to human readable format"""
    return format_bytes(size_bytes)

def sanitize_filename(filename: str) -> str:
    """Sanitize filename by removing invalid characters"""
    import re
    # Remove invalid characters for filenames
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove control characters
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', sanitized)
    return sanitized.strip()