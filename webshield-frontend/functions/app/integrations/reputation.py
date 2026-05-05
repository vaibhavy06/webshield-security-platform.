from typing import Any, Dict
from app.integrations.virustotal import VirusTotalClient

class ReputationService:
    def __init__(self):
        self.vt_client = VirusTotalClient()

    async def check_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Aggregates reputation data from multiple providers.
        """
        vt_data = await self.vt_client.get_domain_report(domain)
        
        # In the future, other providers (e.g., Google Safe Browsing) can be added here
        return {
            "virustotal": vt_data,
            "overall_status": "malicious" if vt_data.get("malicious_count", 0) > 0 else "clean"
        }
