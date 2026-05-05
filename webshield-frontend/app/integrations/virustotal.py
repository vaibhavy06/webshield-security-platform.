import httpx
from typing import Any, Dict
from urllib.parse import urlparse
from app.config import settings

class VirusTotalClient:
    def __init__(self):
        self.api_key = settings.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"

    async def get_domain_report(self, domain: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"status": "skipped", "reason": "VIRUSTOTAL_API_KEY not configured"}

        headers = {
            "x-apikey": self.api_key
        }

        try:
            async with httpx.AsyncClient() as client:
                url = f"{self.base_url}/domains/{domain}"
                response = await client.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    return {
                        "status": "success",
                        "malicious_count": stats.get('malicious', 0),
                        "suspicious_count": stats.get('suspicious', 0),
                        "harmless_count": stats.get('harmless', 0),
                        "undetected_count": stats.get('undetected', 0)
                    }
                else:
                    return {"status": "error", "message": f"VT API returned {response.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}
