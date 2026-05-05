from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class SSLReport(BaseModel):
    valid: bool
    expires_in_days: Optional[int] = None
    issuer: Optional[str] = None
    version: Optional[str] = None
    error: Optional[str] = None

class HeaderReport(BaseModel):
    present_headers: List[str]
    missing_headers: List[str]

class SecuritySummary(BaseModel):
    https: bool
    ssl: Optional[Dict[str, Any]]
    headers: Optional[Dict[str, Any]]

class ScanFindings(BaseModel):
    vulnerabilities: List[Dict[str, Any]]
    content_risks: Dict[str, Any]
    ports: Optional[List[Dict[str, Any]]]

class FullScanReport(BaseModel):
    url: str
    timestamp: str
    summary: str
    security: SecuritySummary
    findings: ScanFindings
    malware: Dict[str, Any]
    risk_score: int
    risk_level: str
    recommendations: List[str]
