import os
from typing import List
from app.scanners.base_scanner import BaseScanner
from app.scanners.header_scanner import HeaderScanner
from app.scanners.ssl_scanner import SSLScanner
from app.scanners.content_scanner import ContentScanner
from app.scanners.port_scanner import PortScanner

class ScannerEngine:
    """
    Registry for all modular scanners. Optimized for Cloud/Serverless.
    """
    def __init__(self):
        # Initializing pure-Python scanners for high-availability cloud deployment
        self._scanners: List[BaseScanner] = [
            HeaderScanner(),
            SSLScanner(),
            ContentScanner(),
            PortScanner(),
        ]
        
        # Optional: Add binary-dependent scanners only if explicitly enabled (Local Mode)
        if os.getenv('ENABLE_BINARY_SCANNERS') == 'true':
            try:
                from app.scanners.zap_scanner import ZAPScanner
                self._scanners.append(ZAPScanner())
            except ImportError:
                pass

    def get_all_scanners(self) -> List[BaseScanner]:
        return self._scanners
