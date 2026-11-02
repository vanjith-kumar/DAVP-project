from typing import Dict, Any, List
import numpy as np
from app.ml.feature_engineering import FeatureExtractor
from app.ml.model_manager import model_manager
import logging

logger = logging.getLogger(__name__)

def score_window(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Scores a window of events.
    Returns the normalized score [0, 1] where 1 is highly anomalous.
    """
    if not model_manager.active_model:
        return {"anomaly_score": 0.0, "classification": "UNAVAILABLE", "message": "ML model not loaded."}
        
    features = FeatureExtractor.extract_features(events)
    X = np.array([[features[k] for k in model_manager.feature_order]])
    
    # decision_function returns raw anomaly score (higher is more normal, lower is more anomalous)
    raw_score = model_manager.active_model.decision_function(X)[0]
    
    # Normalize roughly to [0,1] based on IsolationForest logic
    # Scikit-learn IF scores generally range from -0.5 to +0.5
    # We want 1.0 = Highly anomalous, 0.0 = Normal
    # So we invert and scale
    norm_score = 0.5 - raw_score
    # Cap to [0, 1]
    norm_score = max(0.0, min(1.0, norm_score))
    
    classification = "NORMAL"
    if norm_score >= 0.8:
        classification = "HIGHLY_ANOMALOUS"
    elif norm_score >= 0.6:
        classification = "SUSPICIOUS"
        
    return {
        "anomaly_score": round(norm_score, 3),
        "classification": classification,
        "model_version": model_manager.active_version,
        "features": features
    }
