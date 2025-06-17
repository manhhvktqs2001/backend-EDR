# Fix missing imports in various files

# app/utils/network_utils.py - Complete implementation
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

# app/api/v1/__init__.py - Create this file
"""
API v1 package initialization
"""

# This file makes the v1 directory a Python package

# app/api/__init__.py - Create this file  
"""
API package initialization
"""

# This file makes the api directory a Python package

# app/schemas/threat.py - Fixed field_validator
"""
Threat API Schemas
Pydantic models for threat intelligence API requests and responses
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime

# Threat Request Schemas
class ThreatCreateRequest(BaseModel):
    """Schema for creating new threat indicators"""
    threat_name: str = Field(..., min_length=1, max_length=255, description="Threat name")
    threat_type: str = Field(..., description="Type of indicator (Hash, IP, Domain, URL)")
    threat_value: str = Field(..., description="Indicator value")
    threat_category: Optional[str] = Field(None, description="Threat category")
    severity: str = Field(default="Medium", description="Threat severity")
    description: Optional[str] = Field(None, description="Threat description")
    platform: str = Field(default="All", description="Target platform")
    source: Optional[str] = Field(None, description="Intelligence source")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence score")
    mitre_tactic: Optional[str] = Field(None, description="MITRE ATT&CK tactic")
    mitre_technique: Optional[str] = Field(None, description="MITRE ATT&CK technique")
    
    @field_validator('threat_type')
    @classmethod
    def validate_threat_type(cls, v):
        valid_types = ['Hash', 'IP', 'Domain', 'URL', 'YARA', 'Behavioral']
        if v not in valid_types:
            raise ValueError(f'Threat type must be one of {valid_types}')
        return v
    
    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v):
        valid_severities = ['Low', 'Medium', 'High', 'Critical']
        if v not in valid_severities:
            raise ValueError(f'Severity must be one of {valid_severities}')
        return v

class ThreatLookupRequest(BaseModel):
    """Schema for threat intelligence lookup"""
    indicators: List[str] = Field(..., description="List of indicators to check")
    indicator_type: str = Field(default="all", description="Type of indicators")
    include_inactive: bool = Field(default=False, description="Include inactive threats")
    
    @field_validator('indicator_type')
    @classmethod
    def validate_indicator_type(cls, v):
        valid_types = ['hash', 'ip', 'domain', 'url', 'all']
        if v not in valid_types:
            raise ValueError(f'Indicator type must be one of {valid_types}')
        return v
    
    @field_validator('indicators')
    @classmethod
    def validate_indicators(cls, v):
        if not v:
            raise ValueError('At least one indicator must be provided')
        if len(v) > 1000:
            raise ValueError('Maximum 1000 indicators per lookup')
        return v

# Threat Response Schemas
class ThreatResponse(BaseModel):
    """Schema for detailed threat response"""
    threat_id: int
    threat_name: str
    threat_type: str
    threat_value: str
    threat_category: Optional[str]
    severity: str
    description: Optional[str]
    mitre_tactic: Optional[str]
    mitre_technique: Optional[str]
    platform: str
    threat_source: Optional[str]
    confidence: float
    is_active: bool
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    related_alerts_count: Optional[int] = 0
    recent_detections: Optional[List[Dict]] = []

class ThreatSummary(BaseModel):
    """Schema for threat summary in lists"""
    threat_id: int
    threat_name: str
    threat_type: str
    threat_category: Optional[str]
    severity: str
    confidence: float
    is_active: bool

class ThreatListResponse(BaseModel):
    """Schema for threat list response"""
    threats: List[ThreatSummary]
    total_count: int
    active_count: int
    high_confidence_count: int
    page: int
    page_size: int
    filters_applied: Dict

class ThreatLookupResponse(BaseModel):
    """Schema for threat lookup response"""
    indicators_checked: int
    threats_found: List[Dict[str, Any]]
    clean_indicators: List[str]
    threats_count: int
    clean_count: int
    lookup_timestamp: str

class ThreatStatsResponse(BaseModel):
    """Schema for threat statistics response"""
    total_threats: int
    active_threats: int
    type_breakdown: Dict[str, int]
    severity_breakdown: Dict[str, int]
    recent_additions: int
    high_confidence_threats: int
    platform_distribution: Dict[str, int]
    source_distribution: Dict[str, int]
    top_mitre_techniques: List[Dict[str, Any]]