import ssl
import socket
from datetime import datetime
from typing import Any, Dict
from urllib.parse import urlparse
from app.scanners.base_scanner import BaseScanner

class SSLScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "ssl_scanner"

    async def scan(self, target: str) -> Dict[str, Any]:
        parsed = urlparse(target)
        hostname = parsed.hostname
        port = parsed.port or 443

        if not hostname:
            return self.handle_error(ValueError("Invalid hostname"))

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse dates
                    not_after_str = cert.get('notAfter')
                    expiry_date = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                    remaining_days = (expiry_date - datetime.utcnow()).days
                    
                    issuer = dict(x[0] for x in cert.get('issuer', ()))
                    common_name = issuer.get('commonName', 'Unknown')

                    return {
                        "status": "success",
                        "valid": True,
                        "expires_in_days": remaining_days,
                        "issuer": common_name,
                        "version": ssock.version()
                    }
        except Exception as e:
            return {
                "status": "success", # We return success but with valid: False for risk calculation
                "valid": False,
                "error": str(e)
            }
