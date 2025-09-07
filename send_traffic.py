import requests
import random
import time

# API endpoint
url = 'http://127.0.0.1:5000/predict'

# Feature ranges from generate_dataset.py
FEATURE_RANGES = {
    'benign': {
        'Flow Duration': (50, 5000),  # Microseconds
        'Total Fwd Packets': (1, 10),
        'Total Backward Packets': (0, 8),
        'Fwd Packet Length Total': (50, 1000),  # Bytes
        'Protocol': ['TCP', 'UDP']
    },
    'attack': {
        'Flow Duration': (10, 100),  # Shorter for attacks
        'Total Fwd Packets': (50, 200),  # Higher for attacks (e.g., DDoS)
        'Total Backward Packets': (0, 5),
        'Fwd Packet Length Total': (0, 200),
        'Protocol': ['TCP', 'UDP', 'ICMP']
    }
}

# Simulate 10 packets (70% benign, 30% attack to match dataset distribution)
for i in range(10):
    is_attack = random.choices([True, False], weights=[0.3, 0.7])[0]
    traffic_type = 'attack' if is_attack else 'benign'
    
    # Generate packet data
    packet = {}
    for feature, ranges in FEATURE_RANGES[traffic_type].items():
        if feature == 'Protocol':
            packet[feature] = random.choice(ranges)
        else:
            min_val, max_val = ranges
            packet[feature] = random.randint(min_val, max_val)
    
    # Send POST request
    try:
        response = requests.post(url, json=packet)
        response.raise_for_status()  # Raise exception for bad status codes
        result = response.json()
        print(f"Packet {i+1} ({traffic_type}): {result['result']}, Status: {result['status']}, Type: {result['type']}")
        print(f"Input: {packet}")
    except requests.RequestException as e:
        print(f"Error sending packet {i+1}: {e}")
    
    # Small delay to simulate real-time traffic
    time.sleep(0.5)

print("Traffic simulation completed!")