import asyncio
from datetime import datetime
from typing import Any, Dict
from urllib.parse import urlparse

from app.core.scanner_engine import ScannerEngine
from app.integrations.reputation import ReputationService
from app.scoring.risk_engine import RiskEngine
from app.utils.logger import logger
from app.utils.helpers import run_parallel_tasks

class ScanOrchestrator:
    def __init__(self):
        self.engine = ScannerEngine()
        self.reputation_service = ReputationService()
        self.risk_engine = RiskEngine()

    async def run_scan(self, url: str) -> Dict[str, Any]:
        # Normalize URL logic (usually handled by validator, keeping here for robustness)
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        domain = urlparse(url).netloc
        timestamp = datetime.utcnow().isoformat()
        
        logger.info(f"Starting security scan for: {url}")

        # Run scanners in parallel via Engine
        scanners = self.engine.get_all_scanners()
        scanner_tasks = [s.scan(url) for s in scanners]
        scanner_results = await run_parallel_tasks(scanner_tasks)
        
        # Aggregate scanner results
        aggregated_scanners = {}
        for s, res in zip(scanners, scanner_results):
            if isinstance(res, Exception):
                logger.error(f"Scanner {s.name} failed: {str(res)}")
                aggregated_scanners[s.name] = {"status": "error", "message": str(res)}
            else:
                aggregated_scanners[s.name] = res

        # Run external integrations
        reputation_report = await self.reputation_service.check_reputation(domain)

        # Prepare results for risk engine
        full_results = {
            "url": url,
            "scanners": aggregated_scanners,
            "integrations": reputation_report
        }

        # Calculate risk
        risk_analysis = self.risk_engine.calculate_score(full_results)

        # Final structured report
        report = {
            "url": url,
            "timestamp": timestamp,
            "summary": f"Security analysis for {url} completed.",
            "security": {
                "https": url.startswith('https://'),
                "ssl": aggregated_scanners.get('ssl_scanner'),
                "headers": aggregated_scanners.get('header_scanner')
            },
            "findings": {
                "vulnerabilities": aggregated_scanners.get('zap_scanner', {}).get('findings', []),
                "content_risks": {
                    "inline_scripts": aggregated_scanners.get('content_scanner', {}).get('inline_scripts_count'),
                    "suspicious_iframes": aggregated_scanners.get('content_scanner', {}).get('suspicious_iframes')
                },
                "ports": aggregated_scanners.get('port_scanner', {}).get('open_ports')
            },
            "malware": reputation_report.get('virustotal'),
            "risk_score": risk_analysis['risk_score'],
            "risk_level": risk_analysis['risk_level'],
            "recommendations": risk_analysis['recommendations']
        }

        return report
