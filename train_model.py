import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

# Load and preprocess dataset
def load_data(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset not found at {file_path}. Please ensure the synthetic dataset is generated.")
    df = pd.read_csv(file_path)
    df = df.dropna()  # Drop missing values
    df = df.replace([float('inf'), -float('inf')], 0)  # Handle infinities
    return df

# Load dataset
data_file = 'data/synthetic_network_traffic.csv'  # Your synthetic dataset
df = load_data(data_file)

# Define features (match app.py)
FEATURES = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Fwd Packet Length Total', 'Protocol']
# Verify all features exist in the dataset
missing_features = [f for f in FEATURES if f not in df.columns]
if missing_features:
    raise ValueError(f"Features {missing_features} not found in dataset columns: {df.columns.tolist()}")

# Encode categorical 'Protocol' feature
label_encoder = LabelEncoder()
df['Protocol'] = label_encoder.fit_transform(df['Protocol'])

# Features and target
X = df[FEATURES]
y = df[' Label']  # Keep as 'ATTACK'/'BENIGN' to match app.py

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Scale features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train_scaled, y_train)

# Evaluate model
predictions = model.predict(X_test_scaled)
print("Accuracy:", accuracy_score(y_test, predictions))
print(classification_report(y_test, predictions))

# Save model, scaler, and label encoder
joblib.dump(model, 'model.pkl')
joblib.dump(scaler, 'scaler.pkl')
joblib.dump(label_encoder, 'label_encoder.pkl')
print("Model, scaler, and label encoder saved as 'model.pkl', 'scaler.pkl', and 'label_encoder.pkl'")