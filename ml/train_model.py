"""
Training Script for Login Anomaly Detector (Isolation Forest)
============================================================
Academic Subject: Machine Learning Foundations (MLF)

This script:
1. Synthesizes realistic baseline login event distributions (normal vs. attack/theft patterns).
2. Performs feature preparation.
3. Fits scikit-learn's IsolationForest algorithm.
4. Serializes the trained model to 'isolation_forest.joblib' for production inference.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

def generate_synthetic_login_data(n_samples: int = 1500) -> pd.DataFrame:
    """
    Generates a synthetic dataset modeling typical student/enterprise login distributions:
    - 90% Normal User Logins: Low failed attempts (0-1), daytime/evening hours, low request burst.
    - 10% Malicious/Theft Attempts: High failed attempts (2-5), irregular hours, rapid bursts.
    """
    np.random.seed(42)
    n_normal = int(n_samples * 0.90)
    n_attack = n_samples - n_normal

    # Normal Logins
    normal_failures = np.random.choice([0, 1], size=n_normal, p=[0.88, 0.12])
    normal_hours = np.random.choice(range(8, 23), size=n_normal)  # Daytime (8 AM - 11 PM)
    normal_velocity = np.random.choice([1, 2], size=n_normal, p=[0.90, 0.10])
    normal_night = np.zeros(n_normal, dtype=int)

    # Attack/Theft Logins
    attack_failures = np.random.choice([2, 3, 4, 5], size=n_attack, p=[0.25, 0.45, 0.20, 0.10])
    attack_hours = np.random.choice(range(0, 24), size=n_attack)
    attack_velocity = np.random.choice([3, 4, 5, 8, 12], size=n_attack)
    attack_night = np.array([1 if (h >= 23 or h <= 5) else 0 for h in attack_hours])

    # Combine into DataFrame
    df_normal = pd.DataFrame({
        "failed_attempts": normal_failures,
        "login_hour": normal_hours,
        "attempts_last_10m": normal_velocity,
        "is_night_time": normal_night,
        "label": 1  # Inlier / Normal
    })

    df_attack = pd.DataFrame({
        "failed_attempts": attack_failures,
        "login_hour": attack_hours,
        "attempts_last_10m": attack_velocity,
        "is_night_time": attack_night,
        "label": -1  # Outlier / Anomaly
    })

    df = pd.concat([df_normal, df_attack], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
    return df

def train_and_save_model():
    """Trains the IsolationForest model and writes it to disk."""
    print("[*] Generating synthetic login telemetry data...")
    df = generate_synthetic_login_data(2000)
    
    feature_cols = ["failed_attempts", "login_hour", "attempts_last_10m", "is_night_time"]
    X = df[feature_cols]

    print(f"[*] Training IsolationForest on {len(df)} samples with features: {feature_cols}")
    # IsolationForest with 10% contamination (matching empirical attack ratio)
    model = IsolationForest(
        n_estimators=100,
        contamination=0.10,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X)

    # Validate output
    preds = model.predict(X)
    anomalies_detected = (preds == -1).sum()
    print(f"[+] Model Training Complete! Anomalies detected in baseline: {anomalies_detected}/{len(df)} ({anomalies_detected/len(df)*100:.1f}%)")

    # Serialize model to joblib
    output_path = os.path.join(os.path.dirname(__file__), "isolation_forest.joblib")
    joblib.dump(model, output_path)
    print(f"[+] Model successfully saved to: {output_path}")

if __name__ == "__main__":
    train_and_save_model()
