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

def get_start_of_day(dt: datetime) -> datetime:
    """Get start of day for given datetime"""
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)

def get_end_of_day(dt: datetime) -> datetime:
    """Get end of day for given datetime"""
    return dt.replace(hour=23, minute=59, second=59, microsecond=999999)

def get_time_range(hours: int) -> tuple[datetime, datetime]:
    """Get time range from now minus hours to now"""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)
    return start_time, end_time

def format_duration(seconds: int) -> str:
    """Format duration in seconds to human readable string"""
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