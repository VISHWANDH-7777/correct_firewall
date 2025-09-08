import pandas as pd
import numpy as np
import os

# Create data/ folder if it doesn't exist
if not os.path.exists('data'):
    os.makedirs('data')

# Define attack types and their characteristics
ATTACK_TYPES = {
    'DDoS': {
        'Flow Duration': (10, 500),
        'Total Fwd Packets': (100, 1000),
        'Total Backward Packets': (0, 10),
        'Fwd Packet Length Total': (50, 500),
        'Bwd Packet Length Total': (0, 100),
        'Flow Bytes/s': (10000, 100000),
        'Flow Packets/s': (50, 500),
        'Flow IAT Mean': (1, 50),
        'Fwd IAT Mean': (1, 30),
        'Bwd IAT Mean': (1, 20),
        'Fwd PSH Flags': (0, 5),
        'Bwd PSH Flags': (0, 2),
        'Fwd URG Flags': (0, 1),
        'Bwd URG Flags': (0, 1),
        'Fwd Header Length': (20, 60),
        'Bwd Header Length': (0, 40),
        'Fwd Packets/s': (20, 200),
        'Bwd Packets/s': (0, 50),
        'Min Packet Length': (0, 100),
        'Max Packet Length': (100, 1500),
        'Packet Length Mean': (50, 800),
        'Packet Length Std': (10, 200),
        'Packet Length Variance': (100, 40000),
        'FIN Flag Count': (0, 2),
        'SYN Flag Count': (50, 200),
        'RST Flag Count': (0, 10),
        'PSH Flag Count': (0, 5),
        'ACK Flag Count': (0, 50),
        'URG Flag Count': (0, 2),
        'CWE Flag Count': (0, 1),
        'ECE Flag Count': (0, 1),
        'Down/Up Ratio': (0, 10),
        'Average Packet Size': (50, 800),
        'Avg Fwd Segment Size': (50, 800),
        'Avg Bwd Segment Size': (0, 400),
        'Subflow Fwd Packets': (50, 500),
        'Subflow Fwd Bytes': (1000, 50000),
        'Subflow Bwd Packets': (0, 50),
        'Subflow Bwd Bytes': (0, 5000),
        'Init_Win_bytes_forward': (1000, 65535),
        'Init_Win_bytes_backward': (0, 32768),
        'act_data_pkt_fwd': (20, 200),
        'min_seg_size_forward': (20, 100),
        'Active Mean': (100, 5000),
        'Active Std': (50, 2000),
        'Active Max': (200, 10000),
        'Active Min': (10, 1000),
        'Idle Mean': (0, 1000),
        'Idle Std': (0, 500),
        'Idle Max': (0, 2000),
        'Idle Min': (0, 100),
        'Protocol': ['TCP', 'UDP', 'ICMP']
    },
    'Port Scan': {
        'Flow Duration': (1000, 10000),
        'Total Fwd Packets': (1, 5),
        'Total Backward Packets': (0, 2),
        'Fwd Packet Length Total': (40, 200),
        'Bwd Packet Length Total': (0, 100),
        'Flow Bytes/s': (100, 5000),
        'Flow Packets/s': (1, 10),
        'Flow IAT Mean': (100, 2000),
        'Fwd IAT Mean': (100, 1500),
        'Bwd IAT Mean': (0, 1000),
        'Fwd PSH Flags': (0, 1),
        'Bwd PSH Flags': (0, 1),
        'Fwd URG Flags': (0, 1),
        'Bwd URG Flags': (0, 1),
        'Fwd Header Length': (20, 40),
        'Bwd Header Length': (0, 20),
        'Fwd Packets/s': (1, 5),
        'Bwd Packets/s': (0, 2),
        'Min Packet Length': (40, 100),
        'Max Packet Length': (40, 200),
        'Packet Length Mean': (40, 150),
        'Packet Length Std': (0, 50),
        'Packet Length Variance': (0, 2500),
        'FIN Flag Count': (0, 1),
        'SYN Flag Count': (1, 3),
        'RST Flag Count': (0, 2),
        'PSH Flag Count': (0, 1),
        'ACK Flag Count': (0, 2),
        'URG Flag Count': (0, 1),
        'CWE Flag Count': (0, 1),
        'ECE Flag Count': (0, 1),
        'Down/Up Ratio': (0, 5),
        'Average Packet Size': (40, 150),
        'Avg Fwd Segment Size': (40, 150),
        'Avg Bwd Segment Size': (0, 100),
        'Subflow Fwd Packets': (1, 3),
        'Subflow Fwd Bytes': (40, 300),
        'Subflow Bwd Packets': (0, 2),
        'Subflow Bwd Bytes': (0, 200),
        'Init_Win_bytes_forward': (1000, 32768),
        'Init_Win_bytes_backward': (0, 16384),
        'act_data_pkt_fwd': (1, 3),
        'min_seg_size_forward': (20, 60),
        'Active Mean': (500, 3000),
        'Active Std': (100, 1000),
        'Active Max': (1000, 5000),
        'Active Min': (100, 1000),
        'Idle Mean': (1000, 10000),
        'Idle Std': (500, 5000),
        'Idle Max': (2000, 20000),
        'Idle Min': (500, 5000),
        'Protocol': ['TCP']
    },
    'Brute Force': {
        'Flow Duration': (5000, 30000),
        'Total Fwd Packets': (10, 50),
        'Total Backward Packets': (5, 25),
        'Fwd Packet Length Total': (500, 2000),
        'Bwd Packet Length Total': (200, 1000),
        'Flow Bytes/s': (1000, 20000),
        'Flow Packets/s': (5, 50),
        'Flow IAT Mean': (200, 1000),
        'Fwd IAT Mean': (100, 800),
        'Bwd IAT Mean': (100, 600),
        'Fwd PSH Flags': (5, 20),
        'Bwd PSH Flags': (2, 10),
        'Fwd URG Flags': (0, 2),
        'Bwd URG Flags': (0, 2),
        'Fwd Header Length': (200, 1000),
        'Bwd Header Length': (100, 500),
        'Fwd Packets/s': (5, 25),
        'Bwd Packets/s': (2, 12),
        'Min Packet Length': (50, 200),
        'Max Packet Length': (200, 1500),
        'Packet Length Mean': (100, 800),
        'Packet Length Std': (50, 300),
        'Packet Length Variance': (2500, 90000),
        'FIN Flag Count': (5, 25),
        'SYN Flag Count': (5, 25),
        'RST Flag Count': (0, 5),
        'PSH Flag Count': (5, 20),
        'ACK Flag Count': (10, 40),
        'URG Flag Count': (0, 2),
        'CWE Flag Count': (0, 1),
        'ECE Flag Count': (0, 1),
        'Down/Up Ratio': (0.5, 2),
        'Average Packet Size': (100, 800),
        'Avg Fwd Segment Size': (100, 800),
        'Avg Bwd Segment Size': (50, 400),
        'Subflow Fwd Packets': (5, 25),
        'Subflow Fwd Bytes': (500, 10000),
        'Subflow Bwd Packets': (2, 12),
        'Subflow Bwd Bytes': (200, 5000),
        'Init_Win_bytes_forward': (8192, 65535),
        'Init_Win_bytes_backward': (4096, 32768),
        'act_data_pkt_fwd': (5, 20),
        'min_seg_size_forward': (20, 100),
        'Active Mean': (1000, 10000),
        'Active Std': (500, 5000),
        'Active Max': (2000, 20000),
        'Active Min': (500, 5000),
        'Idle Mean': (500, 5000),
        'Idle Std': (200, 2000),
        'Idle Max': (1000, 10000),
        'Idle Min': (100, 2000),
        'Protocol': ['TCP']
    },
    'Web Attack': {
        'Flow Duration': (1000, 15000),
        'Total Fwd Packets': (5, 30),
        'Total Backward Packets': (3, 20),
        'Fwd Packet Length Total': (300, 3000),
        'Bwd Packet Length Total': (200, 2000),
        'Flow Bytes/s': (2000, 30000),
        'Flow Packets/s': (3, 30),
        'Flow IAT Mean': (50, 500),
        'Fwd IAT Mean': (30, 300),
        'Bwd IAT Mean': (50, 400),
        'Fwd PSH Flags': (3, 15),
        'Bwd PSH Flags': (2, 10),
        'Fwd URG Flags': (0, 1),
        'Bwd URG Flags': (0, 1),
        'Fwd Header Length': (100, 600),
        'Bwd Header Length': (60, 400),
        'Fwd Packets/s': (3, 15),
        'Bwd Packets/s': (2, 10),
        'Min Packet Length': (60, 300),
        'Max Packet Length': (300, 1500),
        'Packet Length Mean': (150, 1000),
        'Packet Length Std': (100, 400),
        'Packet Length Variance': (10000, 160000),
        'FIN Flag Count': (3, 15),
        'SYN Flag Count': (3, 15),
        'RST Flag Count': (0, 3),
        'PSH Flag Count': (3, 15),
        'ACK Flag Count': (5, 25),
        'URG Flag Count': (0, 1),
        'CWE Flag Count': (0, 1),
        'ECE Flag Count': (0, 1),
        'Down/Up Ratio': (0.3, 3),
        'Average Packet Size': (150, 1000),
        'Avg Fwd Segment Size': (150, 1000),
        'Avg Bwd Segment Size': (100, 600),
        'Subflow Fwd Packets': (3, 15),
        'Subflow Fwd Bytes': (300, 15000),
        'Subflow Bwd Packets': (2, 10),
        'Subflow Bwd Bytes': (200, 10000),
        'Init_Win_bytes_forward': (4096, 65535),
        'Init_Win_bytes_backward': (2048, 32768),
        'act_data_pkt_fwd': (3, 12),
        'min_seg_size_forward': (20, 100),
        'Active Mean': (500, 5000),
        'Active Std': (200, 2000),
        'Active Max': (1000, 10000),
        'Active Min': (200, 2000),
        'Idle Mean': (200, 2000),
        'Idle Std': (100, 1000),
        'Idle Max': (500, 5000),
        'Idle Min': (50, 1000),
        'Protocol': ['TCP']
    },
    'Infiltration': {
        'Flow Duration': (10000, 60000),
        'Total Fwd Packets': (20, 100),
        'Total Backward Packets': (15, 80),
        'Fwd Packet Length Total': (1000, 10000),
        'Bwd Packet Length Total': (800, 8000),
        'Flow Bytes/s': (500, 10000),
        'Flow Packets/s': (1, 20),
        'Flow IAT Mean': (500, 3000),
        'Fwd IAT Mean': (300, 2000),
        'Bwd IAT Mean': (400, 2500),
        'Fwd PSH Flags': (10, 50),
        'Bwd PSH Flags': (8, 40),
        'Fwd URG Flags': (0, 3),
        'Bwd URG Flags': (0, 3),
        'Fwd Header Length': (400, 2000),
        'Bwd Header Length': (300, 1600),
        'Fwd Packets/s': (1, 10),
        'Bwd Packets/s': (1, 8),
        'Min Packet Length': (100, 500),
        'Max Packet Length': (500, 1500),
        'Packet Length Mean': (300, 1200),
        'Packet Length Std': (200, 600),
        'Packet Length Variance': (40000, 360000),
        'FIN Flag Count': (10, 50),
        'SYN Flag Count': (10, 50),
        'RST Flag Count': (0, 10),
        'PSH Flag Count': (10, 50),
        'ACK Flag Count': (20, 80),
        'URG Flag Count': (0, 3),
        'CWE Flag Count': (0, 2),
        'ECE Flag Count': (0, 2),
        'Down/Up Ratio': (0.7, 1.5),
        'Average Packet Size': (300, 1200),
        'Avg Fwd Segment Size': (300, 1200),
        'Avg Bwd Segment Size': (250, 1000),
        'Subflow Fwd Packets': (10, 50),
        'Subflow Fwd Bytes': (1000, 50000),
        'Subflow Bwd Packets': (8, 40),
        'Subflow Bwd Bytes': (800, 40000),
        'Init_Win_bytes_forward': (16384, 65535),
        'Init_Win_bytes_backward': (8192, 32768),
        'act_data_pkt_fwd': (10, 40),
        'min_seg_size_forward': (20, 100),
        'Active Mean': (2000, 20000),
        'Active Std': (1000, 10000),
        'Active Max': (5000, 50000),
        'Active Min': (1000, 10000),
        'Idle Mean': (1000, 10000),
        'Idle Std': (500, 5000),
        'Idle Max': (2000, 20000),
        'Idle Min': (500, 5000),
        'Protocol': ['TCP']
    }
}

# Benign traffic characteristics
BENIGN_RANGES = {
    'Flow Duration': (1000, 300000),
    'Total Fwd Packets': (1, 50),
    'Total Backward Packets': (1, 40),
    'Fwd Packet Length Total': (50, 5000),
    'Bwd Packet Length Total': (50, 4000),
    'Flow Bytes/s': (100, 50000),
    'Flow Packets/s': (1, 100),
    'Flow IAT Mean': (10, 10000),
    'Fwd IAT Mean': (10, 8000),
    'Bwd IAT Mean': (10, 6000),
    'Fwd PSH Flags': (0, 10),
    'Bwd PSH Flags': (0, 8),
    'Fwd URG Flags': (0, 2),
    'Bwd URG Flags': (0, 2),
    'Fwd Header Length': (20, 1000),
    'Bwd Header Length': (20, 800),
    'Fwd Packets/s': (1, 25),
    'Bwd Packets/s': (1, 20),
    'Min Packet Length': (20, 500),
    'Max Packet Length': (100, 1500),
    'Packet Length Mean': (60, 1200),
    'Packet Length Std': (10, 500),
    'Packet Length Variance': (100, 250000),
    'FIN Flag Count': (0, 10),
    'SYN Flag Count': (0, 10),
    'RST Flag Count': (0, 5),
    'PSH Flag Count': (0, 10),
    'ACK Flag Count': (1, 40),
    'URG Flag Count': (0, 2),
    'CWE Flag Count': (0, 1),
    'ECE Flag Count': (0, 1),
    'Down/Up Ratio': (0.1, 10),
    'Average Packet Size': (60, 1200),
    'Avg Fwd Segment Size': (60, 1200),
    'Avg Bwd Segment Size': (60, 1000),
    'Subflow Fwd Packets': (1, 25),
    'Subflow Fwd Bytes': (50, 25000),
    'Subflow Bwd Packets': (1, 20),
    'Subflow Bwd Bytes': (50, 20000),
    'Init_Win_bytes_forward': (1024, 65535),
    'Init_Win_bytes_backward': (1024, 65535),
    'act_data_pkt_fwd': (1, 20),
    'min_seg_size_forward': (20, 100),
    'Active Mean': (100, 30000),
    'Active Std': (50, 15000),
    'Active Max': (200, 60000),
    'Active Min': (50, 15000),
    'Idle Mean': (0, 20000),
    'Idle Std': (0, 10000),
    'Idle Max': (0, 40000),
    'Idle Min': (0, 10000),
    'Protocol': ['TCP', 'UDP', 'HTTP', 'HTTPS']
}

def generate_dataset(attack_type, n_samples=5000):
    """Generate dataset for specific attack type"""
    np.random.seed(42)
    data = []
    labels = []
    
    # 70% benign, 30% attack
    for i in range(n_samples):
        is_attack = np.random.choice([0, 1], p=[0.7, 0.3])
        row = {}
        
        if is_attack:
            ranges = ATTACK_TYPES[attack_type]
            label = attack_type.upper()
        else:
            ranges = BENIGN_RANGES
            label = 'BENIGN'
        
        for feature, feature_range in ranges.items():
            if feature == 'Protocol':
                row[feature] = np.random.choice(feature_range)
            else:
                min_val, max_val = feature_range
                if isinstance(min_val, float) or isinstance(max_val, float):
                    row[feature] = np.random.uniform(min_val, max_val)
                else:
                    row[feature] = np.random.randint(min_val, max_val + 1)
        
        data.append(row)
        labels.append(label)
    
    df = pd.DataFrame(data)
    df[' Label'] = labels
    return df

def generate_combined_dataset(n_samples_per_attack=3000):
    """Generate combined dataset with all attack types"""
    np.random.seed(42)
    all_data = []
    
    # Generate benign traffic
    benign_data = []
    benign_labels = []
    for i in range(n_samples_per_attack * 2):  # More benign samples
        row = {}
        for feature, feature_range in BENIGN_RANGES.items():
            if feature == 'Protocol':
                row[feature] = np.random.choice(feature_range)
            else:
                min_val, max_val = feature_range
                if isinstance(min_val, float) or isinstance(max_val, float):
                    row[feature] = np.random.uniform(min_val, max_val)
                else:
                    row[feature] = np.random.randint(min_val, max_val + 1)
        benign_data.append(row)
        benign_labels.append('BENIGN')
    
    benign_df = pd.DataFrame(benign_data)
    benign_df[' Label'] = benign_labels
    all_data.append(benign_df)
    
    # Generate attack data for each attack type
    for attack_type in ATTACK_TYPES.keys():
        attack_data = []
        attack_labels = []
        for i in range(n_samples_per_attack):
            row = {}
            ranges = ATTACK_TYPES[attack_type]
            for feature, feature_range in ranges.items():
                if feature == 'Protocol':
                    row[feature] = np.random.choice(feature_range)
                else:
                    min_val, max_val = feature_range
                    if isinstance(min_val, float) or isinstance(max_val, float):
                        row[feature] = np.random.uniform(min_val, max_val)
                    else:
                        row[feature] = np.random.randint(min_val, max_val + 1)
            attack_data.append(row)
            attack_labels.append(attack_type.upper())
        
        attack_df = pd.DataFrame(attack_data)
        attack_df[' Label'] = attack_labels
        all_data.append(attack_df)
    
    # Combine all datasets
    combined_df = pd.concat(all_data, ignore_index=True)
    
    # Shuffle the dataset
    combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    return combined_df

# Generate individual datasets for each attack type
print("Generating individual attack datasets...")
for attack_type in ATTACK_TYPES.keys():
    df = generate_dataset(attack_type, 5000)
    output_path = f'data/{attack_type.lower().replace(" ", "_")}_dataset.csv'
    df.to_csv(output_path, index=False)
    print(f"Generated {attack_type} dataset: {output_path}")
    print(f"  - Total samples: {len(df)}")
    print(f"  - Attack samples: {len(df[df[' Label'] == attack_type.upper()])}")
    print(f"  - Benign samples: {len(df[df[' Label'] == 'BENIGN'])}")

# Generate combined dataset
print("\nGenerating combined dataset...")
combined_df = generate_combined_dataset(2000)
combined_output_path = 'data/combined_attacks_dataset.csv'
combined_df.to_csv(combined_output_path, index=False)
print(f"Generated combined dataset: {combined_output_path}")
print(f"  - Total samples: {len(combined_df)}")
for label in combined_df[' Label'].unique():
    count = len(combined_df[combined_df[' Label'] == label])
    print(f"  - {label} samples: {count}")

print(f"\nDataset features: {list(combined_df.columns[:-1])}")
print("All datasets generated successfully!")