from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.core.orchestrator import ScanOrchestrator
from app.utils.validators import validate_url, normalize_url
from app.utils.logger import logger

router = APIRouter()
orchestrator = ScanOrchestrator()

class ScanRequest(BaseModel):
    url: str

@router.post("/scan")
async def create_scan(request: ScanRequest):
    """
    Initiate a security scan for the provided URL.
    """
    raw_url = request.url
    
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL is required")
    
    # Validate and Normalize
    normalized_url = normalize_url(raw_url)
    if not validate_url(normalized_url):
        logger.warning(f"Invalid URL attempted: {raw_url}")
        raise HTTPException(status_code=400, detail="Invalid URL format")
    
    try:
        logger.info(f"API request for scan: {normalized_url}")
        report = await orchestrator.run_scan(normalized_url)
        return report
    except Exception as e:
        logger.error(f"Scan failed for {normalized_url}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")
