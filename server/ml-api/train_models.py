"""
Train and save ML models for disk image forensics
This creates pre-trained models for the AFDF system
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import os

# Create models directory if it doesn't exist
os.makedirs("models", exist_ok=True)

print("Creating pre-trained ML models for AFDF...")

# ============================================
# Create synthetic training data
# Based on real forensic analysis features
# ============================================

np.random.seed(42)
n_samples = 1000

# Generate features for AUTHENTIC samples
authentic_samples = int(n_samples * 0.7)  # 70% authentic
tampered_samples = n_samples - authentic_samples  # 30% tampered

# Authentic features (normal disk images)
X_authentic = np.random.rand(authentic_samples, 11)
X_authentic[:, 0] = np.random.uniform(3.5, 6.0, authentic_samples)  # entropy
X_authentic[:, 1] = np.random.uniform(0.1, 0.6, authentic_samples)  # null_ratio
X_authentic[:, 2] = np.random.uniform(0, 2, authentic_samples)  # repeating_chunks
X_authentic[:, 3] = np.random.uniform(0, 1, authentic_samples)  # timestamp_anomalies
X_authentic[:, 4] = np.zeros(authentic_samples)  # has_wiping
X_authentic[:, 5] = np.zeros(authentic_samples)  # has_anti_forensic_tool
X_authentic[:, 6] = np.zeros(authentic_samples)  # has_hidden_data
X_authentic[:, 7] = np.zeros(authentic_samples)  # high_entropy
X_authentic[:, 8] = np.random.uniform(0, 0.1, authentic_samples)  # unknown_filesystem
X_authentic[:, 9] = np.random.uniform(0.1, 50, authentic_samples)  # file_size (GB)
X_authentic[:, 10] = np.ones(authentic_samples)  # sector_alignment

# Tampered features (suspicious patterns)
X_tampered = np.random.rand(tampered_samples, 11)
X_tampered[:, 0] = np.random.uniform(6.5, 8.0, tampered_samples)  # high entropy
X_tampered[:, 1] = np.random.uniform(0.0, 0.3, tampered_samples)  # low null_ratio
X_tampered[:, 2] = np.random.uniform(10, 100, tampered_samples)  # many repeating chunks
X_tampered[:, 3] = np.random.uniform(2, 10, tampered_samples)  # timestamp anomalies
X_tampered[:, 4] = np.ones(tampered_samples)  # wiping detected
X_tampered[:, 5] = np.random.uniform(0, 1, tampered_samples) > 0.7  # anti-forensic tools
X_tampered[:, 6] = np.random.uniform(0, 1, tampered_samples) > 0.8  # hidden data
X_tampered[:, 7] = np.random.uniform(0, 1, tampered_samples) > 0.7  # high entropy
X_tampered[:, 8] = np.random.uniform(0, 1, tampered_samples) > 0.6  # unknown filesystem
X_tampered[:, 9] = np.random.uniform(0.1, 50, tampered_samples)  # file_size
X_tampered[:, 10] = np.random.uniform(0, 1, tampered_samples) > 0.3  # sector alignment

# Combine data
X = np.vstack([X_authentic, X_tampered])
y = np.array([0] * authentic_samples + [1] * tampered_samples)  # 0 = authentic, 1 = tampered

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train Random Forest
print("Training Random Forest classifier...")
rf_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)

# Split for validation
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42
)

rf_model.fit(X_train, y_train)

# Evaluate
train_acc = rf_model.score(X_train, y_train)
test_acc = rf_model.score(X_test, y_test)
print(f"Training accuracy: {train_acc:.3f}")
print(f"Test accuracy: {test_acc:.3f}")

# Save models
print("Saving models...")
joblib.dump(rf_model, "models/random_forest.joblib")
joblib.dump(scaler, "models/scaler.joblib")

# Print feature importance
print("\nFeature Importance:")
feature_names = [
    "entropy", "null_ratio", "repeating_chunks", "timestamp_anomalies",
    "wiping", "anti_forensic_tool", "hidden_data", "high_entropy",
    "unknown_filesystem", "file_size", "sector_alignment"
]
importances = rf_model.feature_importances_
for name, imp in sorted(zip(feature_names, importances), key=lambda x: -x[1]):
    print(f"  {name}: {imp:.3f}")

print("\n✓ Models saved to models/ directory")
print("  - models/random_forest.joblib")
print("  - models/scaler.joblib")
