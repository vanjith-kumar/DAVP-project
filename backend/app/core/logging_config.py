import logging
import sys
from app.core.config import settings

def setup_logging():
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

    # Future: Configure separate loggers for ingestion, ML, etc.
    # logging.getLogger("securelog.ingestion").setLevel(log_level)
    
    # Supress overly verbose loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

setup_logging()
