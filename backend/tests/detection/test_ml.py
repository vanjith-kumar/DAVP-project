import pytest
from app.ml.feature_engineering import FeatureExtractor
from app.ml.scoring import score_window

def test_feature_extraction():
    events = [
        {"event_type": "AUTH_FAILURE", "source_ip": "1.2.3.4", "severity": "WARNING"},
        {"event_type": "AUTH_FAILURE", "source_ip": "1.2.3.4", "severity": "WARNING"},
        {"event_type": "AUTH_SUCCESS", "source_ip": "1.2.3.4", "severity": "INFO"}
    ]
    features = FeatureExtractor.extract_features(events)
    assert features["failed_login_count"] == 2
    assert features["successful_login_count"] == 1
    assert features["unique_source_ip_count"] == 1
    assert features["total_event_count"] == 3

def test_ml_scoring_no_model():
    # Model not loaded yet
    result = score_window([])
    assert result["classification"] == "UNAVAILABLE"
