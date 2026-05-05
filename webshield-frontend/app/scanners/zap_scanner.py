try:
    from zapv2 import ZAPv2
    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False
from typing import Any, Dict
from app.scanners.base_scanner import BaseScanner
from app.config import settings

class ZAPScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "zap_scanner"

    async def scan(self, target: str) -> Dict[str, Any]:
        if not ZAP_AVAILABLE:
            return {"status": "skipped", "reason": "zapv2 library not installed"}
        if not settings.ZAP_API_KEY:
            return {"status": "skipped", "reason": "ZAP_API_KEY not configured"}

        try:
            zap = ZAPv2(apikey=settings.ZAP_API_KEY)
            
            # Start passive scan
            zap.urlopen(target)
            
            # Wait for passive scan to finish
            # In a real production app, we might poll zap.pscan.records_to_scan
            alerts = zap.core.alerts(baseurl=target)
            
            findings = []
            for alert in alerts:
                findings.append({
                    "alert": alert.get('alert'),
                    "risk": alert.get('risk'),
                    "description": alert.get('description'),
                    "solution": alert.get('solution')
                })

            return {
                "status": "success",
                "findings": findings
            }
        except Exception as e:
            return self.handle_error(e)
