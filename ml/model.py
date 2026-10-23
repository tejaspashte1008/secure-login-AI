"""
Machine Learning Anomaly Detection Model (Isolation Forest)
===========================================================
Academic Subject: Machine Learning Foundations (MLF)

Architecture:
- Algorithm: Isolation Forest (Ensemble tree-based unsupervised anomaly detection)
- Intuition: Anomalous login patterns (e.g. repeated failures, odd night hours, sudden velocity)
  require fewer splits to isolate in feature trees than normal benign logins.
- Output: Anomaly decision (-1 for anomaly, 1 for normal) and a normalized Risk Score [0.0 - 1.0].
"""

import os
import joblib
import numpy as np
from datetime import datetime, timezone, timedelta
from typing import Tuple

MODEL_FILE = os.path.join(os.path.dirname(__file__), "isolation_forest.joblib")

class LoginAnomalyDetector:
    """Loads and runs the scikit-learn Isolation Forest model with heuristic fallback."""
    
    def __init__(self):
        self.model = None
        self.feature_names = [
            "failed_attempts",
            "login_hour",
            "attempts_last_10m",
            "is_night_time"
        ]
        self._load_model()

    def _load_model(self):
        """Attempts to load pre-trained model; falls back gracefully if not found."""
        if os.path.exists(MODEL_FILE):
            try:
                self.model = joblib.load(MODEL_FILE)
            except Exception:
                self.model = None

    def extract_features(self, failed_attempts: int, current_time: datetime, recent_attempts_count: int) -> list:
        """
        Feature Engineering for Login Events:
        1. failed_attempts: Number of failed password entries in sequence.
        2. login_hour: 0 to 23 (diurnal pattern).
        3. attempts_last_10m: Velocity/burst rate of requests.
        4. is_night_time: Binary flag (1 if between 23:00 and 05:00, 0 otherwise).
        """
        hour = current_time.hour
        is_night = 1 if (hour >= 23 or hour <= 5) else 0
        return [
            float(failed_attempts),
            float(hour),
            float(recent_attempts_count),
            float(is_night)
        ]

    def predict_risk(self, failed_attempts: int, recent_attempts_count: int = 1) -> Tuple[float, str]:
        """
        Evaluates risk score and prediction label.
        Returns: (risk_score: float [0.0, 1.0], label: str ['NORMAL', 'SUSPICIOUS', 'HIGH_RISK'])
        """
        now = datetime.now(timezone.utc)
        features = self.extract_features(failed_attempts, now, recent_attempts_count)

        # 1. If trained scikit-learn model is available:
        if self.model is not None:
            try:
                import pandas as pd
                features_df = pd.DataFrame([features], columns=self.feature_names)
                # Isolation Forest decision_function returns anomaly score (negative for anomaly)
                raw_score = self.model.decision_function(features_df)[0]
                
                # Transform raw score to [0.0, 1.0] risk index:
                # Lower decision_function means more anomalous -> higher risk
                # Standard decision_function ranges roughly from -0.5 to 0.5
                normalized_risk = float(np.clip(0.5 - raw_score, 0.0, 1.0))
                
                # Overlay domain rule weighting (defense-in-depth)
                if failed_attempts >= 3:
                    normalized_risk = max(normalized_risk, 0.92)
                elif failed_attempts == 2:
                    normalized_risk = max(normalized_risk, 0.65)
                elif failed_attempts == 1:
                    normalized_risk = max(normalized_risk, 0.35)

                label = "NORMAL"
                if normalized_risk >= 0.75:
                    label = "HIGH_RISK"
                elif normalized_risk >= 0.40:
                    label = "SUSPICIOUS"

                return round(normalized_risk, 3), label
            except Exception:
                pass

        # 2. Fallback Heuristic Rule Engine (Guarantees zero downtime if ML model file is missing)
        hour = now.hour
        is_night = (hour >= 23 or hour <= 5)
        
        base_risk = 0.05
        base_risk += failed_attempts * 0.28
        base_risk += min(recent_attempts_count * 0.10, 0.30)
        if is_night:
            base_risk += 0.15

        risk_score = min(max(base_risk, 0.0), 1.0)
        
        label = "NORMAL"
        if risk_score >= 0.75:
            label = "HIGH_RISK"
        elif risk_score >= 0.40:
            label = "SUSPICIOUS"

        return round(risk_score, 3), label

# Singleton instance
detector = LoginAnomalyDetector()
