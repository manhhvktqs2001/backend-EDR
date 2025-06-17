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

class ThreatUpdateRequest(BaseModel):
    """Schema for updating threat indicators"""
    threat_name: Optional[str] = Field(None, min_length=1, max_length=255)
    threat_category: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    is_active: Optional[bool] = None

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

# Threat Intelligence Enrichment
class ThreatEnrichmentRequest(BaseModel):
    """Schema for threat enrichment request"""
    threat_id: int
    enrichment_sources: List[str] = Field(default=["virustotal", "shodan", "abuse_ch"])
    include_reputation: bool = True
    include_geolocation: bool = True
    include_whois: bool = True

class ThreatEnrichmentResponse(BaseModel):
    """Schema for threat enrichment response"""
    threat_id: int
    enrichment_data: Dict[str, Any]
    enrichment_sources: List[str]
    enrichment_timestamp: datetime
    confidence_updated: bool
    new_confidence: Optional[float]

# Threat Feed Management
class ThreatFeedConfig(BaseModel):
    """Schema for threat feed configuration"""
    feed_name: str
    feed_url: str
    feed_type: str = Field(..., pattern="^(json|xml|csv|stix)$")
    update_interval_hours: int = Field(default=24, ge=1, le=168)
    authentication_required: bool = False
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    is_active: bool = True
    auto_import: bool = True
    confidence_score: float = Field(default=0.7, ge=0.0, le=1.0)

class ThreatFeedStatus(BaseModel):
    """Schema for threat feed status"""
    feed_id: int
    feed_name: str
    last_update: Optional[datetime]
    next_update: Optional[datetime]
    status: str  # active, error, disabled
    threats_imported: int
    last_error: Optional[str]
    update_frequency: str

# IOC (Indicator of Compromise) Schemas
class IOCBatch(BaseModel):
    """Schema for batch IOC import"""
    iocs: List[Dict[str, Any]]
    source: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    auto_activate: bool = True
    overwrite_existing: bool = False

class IOCImportResponse(BaseModel):
    """Schema for IOC import response"""
    success: bool
    total_iocs: int
    imported_count: int
    updated_count: int
    skipped_count: int
    errors: List[str]
    import_summary: Dict[str, int]

# Threat Hunting Schemas
class ThreatHuntingQuery(BaseModel):
    """Schema for threat hunting queries"""
    query_name: str
    description: str
    hunt_type: str = Field(..., pattern="^(ioc|behavioral|anomaly|correlation)$")
    query_logic: Dict[str, Any]
    time_range_hours: int = Field(default=24, ge=1, le=8760)
    target_agents: Optional[List[str]] = None
    notification_threshold: int = Field(default=1, ge=1)
    is_active: bool = True

class ThreatHuntingResult(BaseModel):
    """Schema for threat hunting results"""
    hunt_id: int
    query_name: str
    execution_time: datetime
    matches_found: int
    high_confidence_matches: int
    results: List[Dict[str, Any]]
    analysis_summary: str
    recommended_actions: List[str]

# MITRE ATT&CK Integration
class MitreMapping(BaseModel):
    """Schema for MITRE ATT&CK mapping"""
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    sub_technique_id: Optional[str] = None
    sub_technique_name: Optional[str] = None
    description: str
    platforms: List[str]
    data_sources: List[str]

class ThreatMitreAnalysis(BaseModel):
    """Schema for threat MITRE analysis"""
    threat_id: int
    mitre_mappings: List[MitreMapping]
    coverage_percentage: float
    kill_chain_phase: str
    attack_patterns: List[str]
    detection_rules: List[int]
    mitigation_suggestions: List[str]

# Threat Intelligence Sharing
class ThreatSharingRequest(BaseModel):
    """Schema for threat intelligence sharing"""
    threat_ids: List[int]
    sharing_level: str = Field(..., pattern="^(white|green|amber|red)$")
    recipient_organizations: List[str]
    sharing_format: str = Field(default="stix", pattern="^(stix|json|csv)$")
    include_attribution: bool = True
    anonymize_sources: bool = False

class ThreatSharingResponse(BaseModel):
    """Schema for threat sharing response"""
    sharing_id: str
    threats_shared: int
    sharing_level: str
    format: str
    created_at: datetime
    expires_at: Optional[datetime]
    download_url: Optional[str]

# Threat Analysis and Reporting
class ThreatAnalysisRequest(BaseModel):
    """Schema for threat analysis request"""
    analysis_type: str = Field(..., pattern="^(trend|impact|attribution|campaign)$")
    time_range_days: int = Field(default=30, ge=1, le=365)
    threat_categories: Optional[List[str]] = None
    include_predictions: bool = False
    confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)

class ThreatAnalysisResponse(BaseModel):
    """Schema for threat analysis response"""
    analysis_id: str
    analysis_type: str
    time_range: Dict[str, datetime]
    key_findings: List[str]
    threat_trends: Dict[str, Any]
    risk_assessment: Dict[str, float]
    recommendations: List[str]
    confidence_score: float
    data_sources: List[str]
    generated_at: datetime

# Reputation and Scoring
class ReputationScore(BaseModel):
    """Schema for reputation scoring"""
    indicator: str
    indicator_type: str
    reputation_score: float = Field(..., ge=0.0, le=100.0)
    risk_level: str = Field(..., pattern="^(low|medium|high|critical)$")
    contributing_factors: List[str]
    source_scores: Dict[str, float]
    last_updated: datetime
    validity_period: int  # hours

class ReputationRequest(BaseModel):
    """Schema for reputation check request"""
    indicators: List[str]
    include_historical: bool = False
    check_all_sources: bool = True
    return_details: bool = False

class ReputationResponse(BaseModel):
    """Schema for reputation check response"""
    indicators_checked: int
    reputation_scores: List[ReputationScore]
    average_processing_time: float
    sources_consulted: List[str]
    check_timestamp: datetime