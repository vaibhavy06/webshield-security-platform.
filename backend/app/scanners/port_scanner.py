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

        # Fallback: Native Python Socket Scan
        open_ports = []
        common_ports = {21: 'ftp', 22: 'ssh', 80: 'http', 443: 'https'}
        
        for port, name in common_ports.items():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.5)
                    result = s.connect_ex((hostname, port))
                    if result == 0:
                        open_ports.append({
                            "port": port,
                            "name": name,
                            "state": "open",
                            "method": "socket"
                        })
            except:
                continue

        return {
            "status": "success",
            "open_ports": open_ports,
            "message": "Used fallback socket scanner" if not NMAP_AVAILABLE else "Scan completed"
        }
