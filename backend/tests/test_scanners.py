import pytest
import asyncio
from app.scanners.header_scanner import HeaderScanner
from app.scanners.ssl_scanner import SSLScanner
from app.scoring.risk_engine import RiskEngine

@pytest.mark.asyncio
async def test_header_scanner_mock():
    scanner = HeaderScanner()
    # Test with a known reliable URL
    result = await scanner.scan("https://www.google.com")
    assert result['status'] == 'success'
    assert 'present_headers' in result
    assert 'missing_headers' in result

def test_risk_engine_calculation():
    engine = RiskEngine()
    mock_results = {
        "url": "http://example.com",
        "scanners": {
            "header_scanner": {
                "status": "success",
                "missing_headers": ["X-Frame-Options", "Content-Security-Policy"]
            }
        },
        "integrations": {
            "virustotal": {"malicious_count": 0}
        }
    }
    
    analysis = engine.calculate_score(mock_results)
    # 100 - 30 (no https) - 20 (2 missing headers) = 50
    assert analysis['risk_score'] == 50
    assert analysis['risk_level'] == "MODERATE"
