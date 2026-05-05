import httpx
from bs4 import BeautifulSoup
from typing import Any, Dict
from urllib.parse import urlparse
from app.scanners.base_scanner import BaseScanner
from app.config import settings

class ContentScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "content_scanner"

    async def scan(self, target: str) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT, verify=False) as client:
                response = await client.get(target)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Detect inline scripts
                scripts = soup.find_all('script')
                inline_scripts = [s.string for s in scripts if not s.get('src') and s.string]
                
                # Detect suspicious iframes
                iframes = [i.get('src') for i in soup.find_all('iframe') if i.get('src')]
                
                # Detect external domains
                links = [a.get('href') for a in soup.find_all('a') if a.get('href')]
                base_domain = urlparse(target).netloc
                external_domains = set()
                
                for link in links:
                    parsed = urlparse(link)
                    if parsed.netloc and parsed.netloc != base_domain:
                        external_domains.add(parsed.netloc)

                return {
                    "status": "success",
                    "inline_scripts_count": len(inline_scripts),
                    "suspicious_iframes": iframes,
                    "external_domains": list(external_domains),
                    "has_suspicious_content": len(inline_scripts) > 5 # Simple heuristic
                }
        except Exception as e:
            return self.handle_error(e)
