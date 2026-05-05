import httpx
from typing import Any, Dict
from app.scanners.base_scanner import BaseScanner
from app.config import settings

class HeaderScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "header_scanner"

    async def scan(self, target: str) -> Dict[str, Any]:
        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]
        
        try:
            async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT, verify=False) as client:
                response = await client.get(target)
                headers = response.headers
                
                present = []
                missing = []
                
                for header in security_headers:
                    if header in headers:
                        present.append(header)
                    else:
                        missing.append(header)
                
                return {
                    "status": "success",
                    "present_headers": present,
                    "missing_headers": missing
                }
        except Exception as e:
            return self.handle_error(e)
