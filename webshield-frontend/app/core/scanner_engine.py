from typing import List
from app.scanners.base_scanner import BaseScanner
from app.scanners.header_scanner import HeaderScanner
from app.scanners.ssl_scanner import SSLScanner
from app.scanners.content_scanner import ContentScanner
from app.scanners.port_scanner import PortScanner
from app.scanners.zap_scanner import ZAPScanner

class ScannerEngine:
    """
    Registry for all modular scanners.
    """
    def __init__(self):
        self._scanners: List[BaseScanner] = [
            HeaderScanner(),
            SSLScanner(),
            ContentScanner(),
            PortScanner(),
            ZAPScanner()
        ]

    def get_all_scanners(self) -> List[BaseScanner]:
        return self._scanners
