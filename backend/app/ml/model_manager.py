import os
import joblib
from datetime import datetime, timezone
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Assume models are saved in a controlled directory
MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'models')
os.makedirs(MODEL_DIR, exist_ok=True)

class ModelManager:
    def __init__(self):
        self.active_model = None
        self.active_version = None
        self.feature_order = [
            "failed_login_count", "successful_login_count", 
            "unique_source_ip_count", "unique_username_count", 
            "4xx_count", "5xx_count", "total_event_count", "high_severity_count"
        ]

    def save_model(self, model, version: str) -> str:
        safe_version = version.replace("/", "").replace("\\", "")
        path = os.path.join(MODEL_DIR, f"iforest_{safe_version}.joblib")
        joblib.dump(model, path)
        return path
        
    def load_active_model(self, version: str):
        safe_version = version.replace("/", "").replace("\\", "")
        path = os.path.join(MODEL_DIR, f"iforest_{safe_version}.joblib")
        if not os.path.exists(path):
            logger.warning(f"Model {version} not found at {path}")
            return False
            
        try:
            self.active_model = joblib.load(path)
            self.active_version = version
            logger.info(f"Loaded ML model version {version}")
            return True
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            return False

model_manager = ModelManager()
