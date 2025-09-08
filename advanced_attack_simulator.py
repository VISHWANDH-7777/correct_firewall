import requests
import random
import time
import threading
import json
from datetime import datetime
import argparse

class AdvancedAttackSimulator:
    def __init__(self, base_url='http://127.0.0.1:5000'):
        self.base_url = base_url
        self.api_url = f"{base_url}/api/predict"
        self.results = []
        
        # Enhanced attack patterns with more realistic characteristics
        self.attack_patterns = {
            'ddos': {
                'name': 'Distributed Denial of Service',
                'characteristics': {
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
                'intensity_levels': {
                    'low': 0.3,
                    'medium': 0.6,
                    'high': 1.0
                }
            },
            'port_scan': {
                'name': 'Port Scanning Attack',
                'characteristics': {
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
                }
            },
            'brute_force': {
                'name': 'Brute Force Attack',
                'characteristics': {
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
                }
            },
            'web_attack': {
                'name': 'Web Application Attack',
                'characteristics': {
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
                }
            },
            'infiltration': {
                'name': 'Network Infiltration',
                'characteristics': {
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
            },
            'benign': {
                'name': 'Normal Traffic',
                'characteristics': {
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
            }
        }
    
    def generate_packet(self, attack_type, intensity='medium'):
        """Generate a packet with specified attack characteristics"""
        if attack_type not in self.attack_patterns:
            raise ValueError(f"Unknown attack type: {attack_type}")
        
        pattern = self.attack_patterns[attack_type]['characteristics']
        packet = {}
        
        # Apply intensity multiplier for certain attack types
        intensity_multiplier = self.attack_patterns[attack_type].get('intensity_levels', {}).get(intensity, 1.0)
        
        for feature, feature_range in pattern.items():
            if feature == 'Protocol':
                packet[feature] = random.choice(feature_range)
            else:
                min_val, max_val = feature_range
                
                # Apply intensity for attack-related features
                if attack_type != 'benign' and feature in ['Total Fwd Packets', 'Flow Bytes/s', 'Flow Packets/s', 'SYN Flag Count']:
                    min_val = int(min_val * intensity_multiplier)
                    max_val = int(max_val * intensity_multiplier)
                
                if isinstance(min_val, float) or isinstance(max_val, float):
                    packet[feature] = random.uniform(min_val, max_val)
                else:
                    packet[feature] = random.randint(min_val, max_val)
        
        return packet
    
    def send_packet(self, packet):
        """Send a packet to the firewall API"""
        try:
            response = requests.post(self.api_url, json=packet, timeout=10)
            response.raise_for_status()
            result = response.json()
            
            # Store result for analysis
            result['sent_at'] = datetime.now().isoformat()
            result['input_packet'] = packet
            self.results.append(result)
            
            return result
        except requests.RequestException as e:
            print(f"Error sending packet: {e}")
            return None
    
    def simulate_single_attack(self, attack_type, intensity='medium', verbose=True):
        """Simulate a single attack"""
        packet = self.generate_packet(attack_type, intensity)
        result = self.send_packet(packet)
        
        if result and verbose:
            prediction = result.get('prediction', 'Unknown')
            action = result.get('firewall_action', {}).get('action', 'Unknown')
            confidence = result.get('detection_details', {}).get('confidence_scores', {})
            
            print(f"Attack: {attack_type.upper()} ({intensity}) -> Prediction: {prediction}, Action: {action}")
            if confidence:
                max_confidence = max(confidence.values()) * 100
                print(f"  Confidence: {max_confidence:.1f}%")
        
        return result
    
    def simulate_attack_campaign(self, attack_type, count=10, intensity='medium', delay_range=(0.1, 2.0)):
        """Simulate multiple attacks of the same type"""
        print(f"\n🚀 Launching {attack_type.upper()} campaign ({count} attacks, {intensity} intensity)")
        print("-" * 60)
        
        results = []
        for i in range(count):
            result = self.simulate_single_attack(attack_type, intensity, verbose=True)
            if result:
                results.append(result)
            
            # Random delay between attacks
            if i < count - 1:
                delay = random.uniform(*delay_range)
                time.sleep(delay)
        
        return results
    
    def simulate_mixed_traffic(self, duration_seconds=60, attack_ratio=0.3):
        """Simulate mixed traffic (benign + attacks) for a specified duration"""
        print(f"\n🌐 Simulating mixed traffic for {duration_seconds} seconds")
        print(f"Attack ratio: {attack_ratio:.1%}")
        print("-" * 60)
        
        start_time = time.time()
        attack_types = ['ddos', 'port_scan', 'brute_force', 'web_attack', 'infiltration']
        
        while time.time() - start_time < duration_seconds:
            # Decide if this should be an attack or benign traffic
            is_attack = random.random() < attack_ratio
            
            if is_attack:
                attack_type = random.choice(attack_types)
                intensity = random.choice(['low', 'medium', 'high'])
            else:
                attack_type = 'benign'
                intensity = 'medium'
            
            self.simulate_single_attack(attack_type, intensity, verbose=True)
            
            # Random delay between packets
            delay = random.uniform(0.5, 3.0)
            time.sleep(delay)
    
    def simulate_coordinated_attack(self, attack_types, threads=3, packets_per_thread=5):
        """Simulate coordinated multi-vector attack"""
        print(f"\n⚡ Launching coordinated attack with {threads} threads")
        print(f"Attack types: {', '.join(attack_types)}")
        print("-" * 60)
        
        def attack_thread(thread_id, attack_type):
            print(f"Thread {thread_id}: Starting {attack_type} attacks")
            for i in range(packets_per_thread):
                intensity = random.choice(['medium', 'high'])
                result = self.simulate_single_attack(attack_type, intensity, verbose=False)
                if result:
                    prediction = result.get('prediction', 'Unknown')
                    action = result.get('firewall_action', {}).get('action', 'Unknown')
                    print(f"Thread {thread_id}: {attack_type} -> {prediction} ({action})")
                time.sleep(random.uniform(0.1, 1.0))
        
        # Start threads
        threads_list = []
        for i, attack_type in enumerate(attack_types[:threads]):
            thread = threading.Thread(target=attack_thread, args=(i+1, attack_type))
            threads_list.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads_list:
            thread.join()
        
        print("Coordinated attack completed!")
    
    def analyze_results(self):
        """Analyze simulation results"""
        if not self.results:
            print("No results to analyze")
            return
        
        print(f"\n📊 Analysis of {len(self.results)} packets:")
        print("=" * 50)
        
        # Count predictions
        predictions = {}
        actions = {}
        
        for result in self.results:
            pred = result.get('prediction', 'Unknown')
            action = result.get('firewall_action', {}).get('action', 'Unknown')
            
            predictions[pred] = predictions.get(pred, 0) + 1
            actions[action] = actions.get(action, 0) + 1
        
        print("Predictions:")
        for pred, count in sorted(predictions.items()):
            percentage = (count / len(self.results)) * 100
            print(f"  {pred}: {count} ({percentage:.1f}%)")
        
        print("\nActions:")
        for action, count in sorted(actions.items()):
            percentage = (count / len(self.results)) * 100
            print(f"  {action}: {count} ({percentage:.1f}%)")
        
        # Calculate detection accuracy (if we know the true labels)
        correct_detections = 0
        total_attacks = 0
        
        for result in self.results:
            packet = result.get('input_packet', {})
            prediction = result.get('prediction', 'Unknown')
            
            # Try to infer true label from packet characteristics
            true_label = self.infer_true_label(packet)
            if true_label != 'Unknown':
                total_attacks += 1
                if (true_label == 'BENIGN' and prediction == 'BENIGN') or \
                   (true_label != 'BENIGN' and prediction != 'BENIGN'):
                    correct_detections += 1
        
        if total_attacks > 0:
            accuracy = (correct_detections / total_attacks) * 100
            print(f"\nDetection Accuracy: {accuracy:.1f}% ({correct_detections}/{total_attacks})")
    
    def infer_true_label(self, packet):
        """Infer the true label of a packet based on its characteristics"""
        # Simple heuristics to infer attack type
        fwd_packets = packet.get('Total Fwd Packets', 0)
        flow_duration = packet.get('Flow Duration', 0)
        syn_flags = packet.get('SYN Flag Count', 0)
        psh_flags = packet.get('PSH Flag Count', 0)
        flow_bytes_per_sec = packet.get('Flow Bytes/s', 0)
        
        # DDoS characteristics
        if fwd_packets > 50 and flow_bytes_per_sec > 10000 and syn_flags > 20:
            return 'DDOS'
        
        # Port scan characteristics
        if fwd_packets <= 5 and flow_duration > 1000 and syn_flags >= 1:
            return 'PORT_SCAN'
        
        # Brute force characteristics
        if flow_duration > 5000 and psh_flags > 5:
            return 'BRUTE_FORCE'
        
        # Web attack characteristics
        if 5 <= fwd_packets <= 30 and psh_flags >= 3:
            return 'WEB_ATTACK'
        
        # Infiltration characteristics
        if flow_duration > 10000 and fwd_packets > 20:
            return 'INFILTRATION'
        
        # Benign characteristics
        if fwd_packets <= 50 and flow_duration <= 300000 and syn_flags <= 10:
            return 'BENIGN'
        
        return 'Unknown'
    
    def save_results(self, filename='simulation_results.json'):
        """Save results to file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"Results saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description='Advanced Attack Simulator for AI Firewall')
    parser.add_argument('--mode', choices=['single', 'campaign', 'mixed', 'coordinated'], 
                       default='single', help='Simulation mode')
    parser.add_argument('--attack', choices=['ddos', 'port_scan', 'brute_force', 'web_attack', 'infiltration', 'benign'],
                       default='ddos', help='Attack type for single/campaign mode')
    parser.add_argument('--count', type=int, default=10, help='Number of attacks for campaign mode')
    parser.add_argument('--intensity', choices=['low', 'medium', 'high'], default='medium',
                       help='Attack intensity')
    parser.add_argument('--duration', type=int, default=60, help='Duration for mixed traffic mode (seconds)')
    parser.add_argument('--threads', type=int, default=3, help='Number of threads for coordinated attack')
    parser.add_argument('--url', default='http://127.0.0.1:5000', help='Firewall API URL')
    
    args = parser.parse_args()
    
    simulator = AdvancedAttackSimulator(args.url)
    
    print("🛡️  Advanced AI Firewall Attack Simulator")
    print("=" * 50)
    
    try:
        if args.mode == 'single':
            simulator.simulate_single_attack(args.attack, args.intensity)
        
        elif args.mode == 'campaign':
            simulator.simulate_attack_campaign(args.attack, args.count, args.intensity)
        
        elif args.mode == 'mixed':
            simulator.simulate_mixed_traffic(args.duration)
        
        elif args.mode == 'coordinated':
            attack_types = ['ddos', 'port_scan', 'brute_force', 'web_attack', 'infiltration']
            simulator.simulate_coordinated_attack(attack_types, args.threads)
        
        # Analyze and save results
        simulator.analyze_results()
        simulator.save_results()
        
    except KeyboardInterrupt:
        print("\n\nSimulation interrupted by user")
        simulator.analyze_results()
        simulator.save_results()
    except Exception as e:
        print(f"Error during simulation: {e}")

if __name__ == "__main__":
    main()