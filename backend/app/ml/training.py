from sklearn.ensemble import IsolationForest
import numpy as np
from typing import List, Dict
import logging
import uuid
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession

from app.ml.feature_engineering import FeatureExtractor
from app.ml.model_manager import model_manager
from app.database.models import MLModel

logger = logging.getLogger(__name__)

async def train_isolation_forest(db: AsyncSession, windows: List[List[Dict]]):
    """
    Trains the Isolation Forest using the provided data windows.
    In a real system, this pulls from DB. Here we accept windows directly.
    """
    if not windows:
        logger.warning("No data for ML training.")
        return None
        
    X = []
    for window in windows:
        features = FeatureExtractor.extract_features(window)
        row = [features[k] for k in model_manager.feature_order]
        X.append(row)
        
    X_array = np.array(X)
    
    # Train
    clf = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
    clf.fit(X_array)
    
    version = f"v_{uuid.uuid4().hex[:8]}"
    path = model_manager.save_model(clf, version)
    
    # Save metadata to DB
    db_model = MLModel(
        model_type="IsolationForest",
        model_version=version,
        status="ACTIVE",
        feature_version="1.0",
        window_size=300, # 5 minutes
        training_event_count=sum(len(w) for w in windows),
        trained_at=datetime.now(timezone.utc),
        path=path
    )
    db.add(db_model)
    await db.commit()
    
    # Activate
    model_manager.load_active_model(version)
    
    return version
