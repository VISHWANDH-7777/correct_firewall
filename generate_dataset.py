import pandas as pd
import numpy as np
import os

# Create data/ folder if it doesn't exist
if not os.path.exists('data'):
    os.makedirs('data')

# Define features and their characteristics
features = {
    'Flow Duration': {'benign': (50, 5000), 'attack': (10, 100)},  # Microseconds; attacks are shorter
    'Total Fwd Packets': {'benign': (1, 10), 'attack': (50, 200)},  # Higher for attacks (e.g., DDoS)
    'Total Backward Packets': {'benign': (0, 8), 'attack': (0, 5)},
    'Fwd Packet Length Total': {'benign': (50, 1000), 'attack': (0, 200)},  # Bytes
    'Protocol': {'benign': ['TCP', 'UDP'], 'attack': ['TCP', 'UDP', 'ICMP']}  # Categorical
}

# Generate synthetic data
np.random.seed(42)  # For reproducibility
n_samples = 10000  # Adjustable
data = []
labels = []

for i in range(n_samples):
    is_attack = np.random.choice([0, 1], p=[0.7, 0.3])  # 70% benign, 30% attack
    row = {}
    for feature, ranges in features.items():
        if feature == 'Protocol':
            row[feature] = np.random.choice(ranges['attack' if is_attack else 'benign'])
        else:
            min_val, max_val = ranges['attack' if is_attack else 'benign']
            row[feature] = np.random.randint(min_val, max_val + 1)
    data.append(row)
    labels.append('ATTACK' if is_attack else 'BENIGN')

# Create DataFrame
df = pd.DataFrame(data)
df[' Label'] = labels  # Space in ' Label' to match CIC-IDS2017 format

# Save to CSV
output_path = 'data/synthetic_network_traffic.csv'
df.to_csv(output_path, index=False)
print(f"Dataset generated and saved to {output_path}")
print(f"Columns: {df.columns.tolist()}")
print(f"Sample rows:\n{df.head()}")