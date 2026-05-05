import nmap
from typing import Any, Dict
from urllib.parse import urlparse
from app.scanners.base_scanner import BaseScanner

class PortScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "port_scanner"

    async def scan(self, target: str) -> Dict[str, Any]:
        parsed = urlparse(target)
        hostname = parsed.hostname
        
        if not hostname:
            return self.handle_error(ValueError("Invalid hostname"))

        try:
            nm = nmap.PortScanner()
            # Scan common ports: 21, 22, 80, 443
            nm.scan(hostname, '21,22,80,443')
            
            open_ports = []
            if hostname in nm.all_hosts():
                for proto in nm[hostname].all_protocols():
                    lport = nm[hostname][proto].keys()
                    for port in lport:
                        if nm[hostname][proto][port]['state'] == 'open':
                            open_ports.append({
                                "port": port,
                                "name": nm[hostname][proto][port]['name'],
                                "state": "open"
                            })

            return {
                "status": "success",
                "open_ports": open_ports
            }
        except Exception as e:
            return self.handle_error(e)
