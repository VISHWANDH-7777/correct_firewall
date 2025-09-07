import requests
import random
import time

# API endpoint
url = 'http://127.0.0.1:5000/predict'

# Attack traffic ranges (mimicking SYN flood: high packet count, short duration)
ATTACK_RANGES = {
    'Flow Duration': (10, 100),  # Short duration for attacks
    'Total Fwd Packets': (50, 200),  # High packets for SYN flood
    'Total Backward Packets': (0, 5),  # Few or no responses
    'Fwd Packet Length Total': (0, 200),  # Small payloads
    'Protocol': ['TCP', 'ICMP']  # SYN flood typically uses TCP
}

# Simulate 10 attack packets
for i in range(10):
    # Generate attack packet data
    packet = {}
    for feature, ranges in ATTACK_RANGES.items():
        if feature == 'Protocol':
            packet[feature] = random.choice(ranges)
        else:
            min_val, max_val = ranges
            packet[feature] = random.randint(min_val, max_val)
    
    # Send POST request
    try:
        response = requests.post(url, json=packet)
        response.raise_for_status()
        result = response.json()
        print(f"SYN Flood Packet {i+1}: {result['result']}, Status: {result['status']}, Type: {result['type']}")
        print(f"Input: {packet}")
    except requests.RequestException as e:
        print(f"Error sending packet {i+1}: {e}")
    
    # Small delay to simulate attack pacing
    time.sleep(0.1)

print("Simulated SYN flood completed!")