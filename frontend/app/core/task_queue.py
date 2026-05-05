from celery import Celery
from app.config import settings
import asyncio
from app.core.orchestrator import ScanOrchestrator

celery_app = Celery(
    "webshield",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL
)

@celery_app.task(name="run_background_scan")
def run_background_scan(url: str):
    """
    Celery task for running scans in the background.
    Useful for large scale scanning or when API response time isn't critical.
    """
    orchestrator = ScanOrchestrator()
    loop = asyncio.get_event_loop()
    report = loop.run_until_complete(orchestrator.run_scan(url))
    
    # Here you would typically save the report to a database
    return report
