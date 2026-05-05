import socket
from typing import Any, Dict
from urllib.parse import urlparse
from app.scanners.base_scanner import BaseScanner

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

class PortScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "port_scanner"

    async def scan(self, target: str) -> Dict[str, Any]:
        parsed = urlparse(target)
        hostname = parsed.hostname
        
        if not hostname:
            return self.handle_error(ValueError("Invalid hostname"))

        # Try Nmap first if available
        if NMAP_AVAILABLE:
            try:
                nm = nmap.PortScanner()
                nm.scan(hostname, '21,22,80,443', arguments='-T4')
                
                open_ports = []
                if hostname in nm.all_hosts():
                    for proto in nm[hostname].all_protocols():
                        for port in nm[hostname][proto].keys():
                            if nm[hostname][proto][port]['state'] == 'open':
                                open_ports.append({
                                    "port": port,
                                    "name": nm[hostname][proto][port]['name'],
                                    "state": "open",
                                    "method": "nmap"
                                })
                return {"status": "success", "open_ports": open_ports}
            except Exception:
                pass # Fallback to socket scan

        # Fallback: Async Socket Scan
        open_ports = []
        common_ports = {21: 'ftp', 22: 'ssh', 80: 'http', 443: 'https'}
        
        import asyncio
        async def check_port(port, name):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port), 
                    timeout=0.5
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return {
                    "port": port,
                    "name": name,
                    "state": "open",
                    "method": "socket"
                }
            except Exception:
                return None

        tasks = [check_port(port, name) for port, name in common_ports.items()]
        results = await asyncio.gather(*tasks)
        open_ports = [r for r in results if r is not None]

        return {
            "status": "success",
            "open_ports": open_ports,
            "message": "Used fallback async socket scanner" if not NMAP_AVAILABLE else "Scan completed"
        }
