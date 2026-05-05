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
        if not url.startswith(('http://', 'https://')):
            url = f"https://{url}"
        
        domain = urlparse(url).netloc
        timestamp = datetime.utcnow().isoformat()
        
        logger.info(f"INITIATING_CORE_AUDIT: {url}")

        try:
            # 1. Parallel Scanner Execution
            scanners = self.engine.get_all_scanners()
            scanner_tasks = [s.scan(url) for s in scanners]
            scanner_results = await run_parallel_tasks(scanner_tasks)
            
            # 2. Defensive Aggregation
            aggregated_scanners = {}
            for s, res in zip(scanners, scanner_results):
                if isinstance(res, Exception):
                    logger.error(f"MODULE_FAILURE [{s.name}]: {str(res)}")
                    aggregated_scanners[s.name] = {"status": "degraded", "message": str(res)}
                else:
                    aggregated_scanners[s.name] = res

            # 3. Reputation Intel (with timeout protection)
            try:
                reputation_report = await asyncio.wait_for(
                    self.reputation_service.check_reputation(domain),
                    timeout=10.0
                )
            except asyncio.TimeoutError:
                logger.warning("REPUTATION_TIMEOUT: Proceeding with local scan only.")
                reputation_report = {"virustotal": {"status": "timeout"}}

            # 4. Risk Synthesis
            full_results = {
                "url": url,
                "scanners": aggregated_scanners,
                "integrations": reputation_report
            }
            risk_analysis = self.risk_engine.calculate_score(full_results)

            # 5. High-Fidelity Report Construction
            report = {
                "url": url,
                "timestamp": timestamp,
                "audit_id": f"WS-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "security": {
                    "https_enforced": url.startswith('https://'),
                    "ssl_intelligence": aggregated_scanners.get('ssl_scanner'),
                    "header_analysis": aggregated_scanners.get('header_scanner')
                },
                "vulnerability_matrix": {
                    "vulnerabilities": aggregated_scanners.get('zap_scanner', {}).get('findings', []),
                    "port_map": aggregated_scanners.get('port_scanner', {}).get('open_ports', []),
                    "content_anomalies": {
                        "inline_scripts": aggregated_scanners.get('content_scanner', {}).get('inline_scripts_count', 0),
                        "suspicious_objects": aggregated_scanners.get('content_scanner', {}).get('suspicious_iframes', [])
                    }
                },
                "threat_intel": reputation_report.get('virustotal'),
                "risk_score": risk_analysis['risk_score'],
                "risk_level": risk_analysis['risk_level'],
                "recommendations": risk_analysis['recommendations']
            }

            logger.info(f"AUDIT_COMPLETED: {url} | SCORE: {risk_analysis['risk_score']}")
            return report

        except Exception as e:
            logger.critical(f"ORCHESTRATOR_CRASH: {str(e)}")
            raise e
