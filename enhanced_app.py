from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
import joblib
import numpy as np
import pandas as pd
import os
from datetime import datetime
import json

app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins="*")

class EnhancedFirewall:
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.label_encoders = {}
        self.feature_names = {}
        self.load_models()
        
        # Enhanced stats tracking
        self.stats = {
            'total': 0,
            'blocked': 0,
            'allowed': 0,
            'attack_types': {
                'DDOS': 0,
                'PORT_SCAN': 0,
                'BRUTE_FORCE': 0,
                'WEB_ATTACK': 0,
                'INFILTRATION': 0
            },
            'recent_attacks': [],
            'hourly_stats': {}
        }
        
        # Load attack patterns for detection
        self.attack_patterns = self.load_attack_patterns()
    
    def load_models(self):
        """Load all trained models"""
        model_types = ['combined', 'ddos', 'port_scan', 'brute_force', 'web_attack', 'infiltration']
        
        for model_type in model_types:
            try:
                self.models[model_type] = joblib.load(f'{model_type}_model.pkl')
                self.scalers[model_type] = joblib.load(f'{model_type}_scaler.pkl')
                
                # Load label encoder if exists
                encoder_path = f'{model_type}_label_encoder.pkl'
                if os.path.exists(encoder_path):
                    self.label_encoders[model_type] = joblib.load(encoder_path)
                
                # Load feature names
                features_path = f'{model_type}_features.txt'
                if os.path.exists(features_path):
                    with open(features_path, 'r') as f:
                        self.feature_names[model_type] = [line.strip() for line in f.readlines()]
                
                print(f"Loaded {model_type} model successfully")
            except FileNotFoundError:
                print(f"Model files for {model_type} not found")
    
    def load_attack_patterns(self):
        """Load attack patterns for enhanced detection"""
        return {
            'DDOS': {
                'min_packets': 100,
                'max_duration': 1000,
                'min_bytes_per_sec': 10000
            },
            'PORT_SCAN': {
                'max_packets': 5,
                'min_duration': 1000,
                'syn_flag_threshold': 1
            },
            'BRUTE_FORCE': {
                'min_duration': 5000,
                'min_packets': 10,
                'psh_flag_threshold': 5
            },
            'WEB_ATTACK': {
                'min_packet_size': 150,
                'protocol': 'TCP',
                'psh_flag_threshold': 3
            },
            'INFILTRATION': {
                'min_duration': 10000,
                'min_packets': 20,
                'balanced_traffic': True
            }
        }
    
    def extract_features(self, data, model_type='combined'):
        """Extract and validate features from input data"""
        if model_type not in self.feature_names:
            model_type = 'combined'
        
        required_features = self.feature_names.get(model_type, [])
        if not required_features:
            # Fallback to basic features
            required_features = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 
                               'Fwd Packet Length Total', 'Protocol']
        
        features = []
        for feature in required_features:
            if feature == 'Protocol':
                # Handle protocol encoding
                protocol_val = data.get(feature, 'TCP')
                if model_type in self.label_encoders:
                    try:
                        encoded_val = self.label_encoders[model_type].transform([protocol_val])[0]
                    except ValueError:
                        encoded_val = 0  # Default for unknown protocols
                else:
                    # Simple encoding
                    protocol_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'HTTP': 3, 'HTTPS': 4}
                    encoded_val = protocol_map.get(protocol_val, 0)
                features.append(encoded_val)
            else:
                # Numerical features with defaults
                default_value = self.get_feature_default(feature)
                features.append(float(data.get(feature, default_value)))
        
        return np.array([features])
    
    def get_feature_default(self, feature):
        """Get default value for missing features"""
        defaults = {
            'Flow Duration': 1000,
            'Total Fwd Packets': 5,
            'Total Backward Packets': 3,
            'Fwd Packet Length Total': 300,
            'Bwd Packet Length Total': 200,
            'Flow Bytes/s': 1000,
            'Flow Packets/s': 10,
            'Flow IAT Mean': 100,
            'Fwd IAT Mean': 80,
            'Bwd IAT Mean': 90,
            'Fwd PSH Flags': 1,
            'Bwd PSH Flags': 1,
            'Fwd URG Flags': 0,
            'Bwd URG Flags': 0,
            'Fwd Header Length': 40,
            'Bwd Header Length': 40,
            'Fwd Packets/s': 5,
            'Bwd Packets/s': 3,
            'Min Packet Length': 60,
            'Max Packet Length': 1500,
            'Packet Length Mean': 400,
            'Packet Length Std': 100,
            'Packet Length Variance': 10000,
            'FIN Flag Count': 1,
            'SYN Flag Count': 1,
            'RST Flag Count': 0,
            'PSH Flag Count': 1,
            'ACK Flag Count': 3,
            'URG Flag Count': 0,
            'CWE Flag Count': 0,
            'ECE Flag Count': 0,
            'Down/Up Ratio': 1,
            'Average Packet Size': 400,
            'Avg Fwd Segment Size': 400,
            'Avg Bwd Segment Size': 300,
            'Subflow Fwd Packets': 3,
            'Subflow Fwd Bytes': 1200,
            'Subflow Bwd Packets': 2,
            'Subflow Bwd Bytes': 800,
            'Init_Win_bytes_forward': 8192,
            'Init_Win_bytes_backward': 8192,
            'act_data_pkt_fwd': 2,
            'min_seg_size_forward': 20,
            'Active Mean': 1000,
            'Active Std': 500,
            'Active Max': 2000,
            'Active Min': 500,
            'Idle Mean': 1000,
            'Idle Std': 500,
            'Idle Max': 2000,
            'Idle Min': 500
        }
        return defaults.get(feature, 0)
    
    def enhanced_detection(self, data, predictions):
        """Enhanced detection using multiple models and pattern matching"""
        detection_results = {}
        confidence_scores = {}
        
        # Get predictions from all available models
        for model_type, model in self.models.items():
            if model_type == 'combined':
                continue
                
            try:
                features = self.extract_features(data, model_type)
                features_scaled = self.scalers[model_type].transform(features)
                prediction = model.predict(features_scaled)[0]
                probability = model.predict_proba(features_scaled)[0]
                
                detection_results[model_type] = prediction
                confidence_scores[model_type] = max(probability)
                
            except Exception as e:
                print(f"Error in {model_type} detection: {e}")
                continue
        
        # Pattern-based detection
        pattern_matches = self.pattern_based_detection(data)
        
        # Combine results
        final_prediction = self.combine_predictions(detection_results, pattern_matches, confidence_scores)
        
        return final_prediction, detection_results, confidence_scores, pattern_matches
    
    def pattern_based_detection(self, data):
        """Pattern-based attack detection"""
        matches = {}
        
        for attack_type, patterns in self.attack_patterns.items():
            score = 0
            total_checks = len(patterns)
            
            for pattern_key, threshold in patterns.items():
                if pattern_key == 'min_packets' and data.get('Total Fwd Packets', 0) >= threshold:
                    score += 1
                elif pattern_key == 'max_packets' and data.get('Total Fwd Packets', 0) <= threshold:
                    score += 1
                elif pattern_key == 'min_duration' and data.get('Flow Duration', 0) >= threshold:
                    score += 1
                elif pattern_key == 'max_duration' and data.get('Flow Duration', 0) <= threshold:
                    score += 1
                elif pattern_key == 'min_bytes_per_sec' and data.get('Flow Bytes/s', 0) >= threshold:
                    score += 1
                elif pattern_key == 'syn_flag_threshold' and data.get('SYN Flag Count', 0) >= threshold:
                    score += 1
                elif pattern_key == 'psh_flag_threshold' and data.get('PSH Flag Count', 0) >= threshold:
                    score += 1
                elif pattern_key == 'protocol' and data.get('Protocol', '') == threshold:
                    score += 1
                elif pattern_key == 'min_packet_size' and data.get('Average Packet Size', 0) >= threshold:
                    score += 1
                elif pattern_key == 'balanced_traffic':
                    fwd_packets = data.get('Total Fwd Packets', 0)
                    bwd_packets = data.get('Total Backward Packets', 0)
                    if fwd_packets > 0 and bwd_packets > 0:
                        ratio = bwd_packets / fwd_packets
                        if 0.5 <= ratio <= 2.0:  # Balanced traffic
                            score += 1
            
            matches[attack_type] = score / total_checks if total_checks > 0 else 0
        
        return matches
    
    def combine_predictions(self, ml_results, pattern_matches, confidence_scores):
        """Combine ML predictions with pattern matching"""
        attack_scores = {}
        
        # Weight ML predictions by confidence
        for model_type, prediction in ml_results.items():
            if prediction != 'BENIGN':
                attack_type = prediction.replace('_', ' ').upper()
                confidence = confidence_scores.get(model_type, 0.5)
                attack_scores[attack_type] = attack_scores.get(attack_type, 0) + confidence
        
        # Add pattern matching scores
        for attack_type, pattern_score in pattern_matches.items():
            if pattern_score > 0.5:  # Threshold for pattern match
                attack_scores[attack_type] = attack_scores.get(attack_type, 0) + pattern_score
        
        # Determine final prediction
        if not attack_scores:
            return 'BENIGN'
        
        # Return attack type with highest score
        return max(attack_scores, key=attack_scores.get)
    
    def update_stats(self, prediction, data):
        """Update comprehensive statistics"""
        self.stats['total'] += 1
        current_hour = datetime.now().strftime('%Y-%m-%d %H:00')
        
        if current_hour not in self.stats['hourly_stats']:
            self.stats['hourly_stats'][current_hour] = {'blocked': 0, 'allowed': 0}
        
        if prediction == 'BENIGN':
            self.stats['allowed'] += 1
            self.stats['hourly_stats'][current_hour]['allowed'] += 1
        else:
            self.stats['blocked'] += 1
            self.stats['hourly_stats'][current_hour]['blocked'] += 1
            
            # Update attack type stats
            if prediction in self.stats['attack_types']:
                self.stats['attack_types'][prediction] += 1
            
            # Add to recent attacks
            attack_info = {
                'type': prediction,
                'timestamp': datetime.now().isoformat(),
                'source_data': {k: v for k, v in data.items() if k in ['Protocol', 'Total Fwd Packets', 'Flow Duration']}
            }
            self.stats['recent_attacks'].insert(0, attack_info)
            
            # Keep only last 50 attacks
            if len(self.stats['recent_attacks']) > 50:
                self.stats['recent_attacks'] = self.stats['recent_attacks'][:50]
    
    def virtual_firewall_action(self, prediction, confidence_info):
        """Enhanced virtual firewall with detailed actions"""
        if prediction == 'BENIGN':
            return {
                'action': 'ALLOW',
                'message': 'Traffic allowed - appears benign',
                'rule': 'default_allow'
            }
        else:
            return {
                'action': 'BLOCK',
                'message': f'Traffic blocked - {prediction} detected',
                'rule': f'block_{prediction.lower()}',
                'confidence': confidence_info
            }

# Initialize enhanced firewall
firewall = EnhancedFirewall()

@app.route('/')
def index():
    return render_template('enhanced_dashboard.html')

@app.route('/api/stats')
def get_stats():
    """Get comprehensive statistics"""
    return jsonify(firewall.stats)

@app.route('/api/predict', methods=['POST'])
def predict():
    """Enhanced prediction endpoint"""
    try:
        data = request.json
        
        # Enhanced detection
        prediction, ml_results, confidence_scores, pattern_matches = firewall.enhanced_detection(data)
        
        # Update statistics
        firewall.update_stats(prediction, data)
        
        # Get firewall action
        firewall_action = firewall.virtual_firewall_action(prediction, {
            'ml_results': ml_results,
            'confidence_scores': confidence_scores,
            'pattern_matches': pattern_matches
        })
        
        # Prepare response
        response = {
            'prediction': prediction,
            'firewall_action': firewall_action,
            'detection_details': {
                'ml_results': ml_results,
                'confidence_scores': confidence_scores,
                'pattern_matches': pattern_matches
            },
            'timestamp': datetime.now().isoformat()
        }
        
        # Emit real-time update
        socketio.emit('detection_update', {
            'stats': firewall.stats,
            'latest_detection': response
        })
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500

@app.route('/api/attack_patterns')
def get_attack_patterns():
    """Get attack patterns for frontend"""
    return jsonify(firewall.attack_patterns)

if __name__ == '__main__':
    if not firewall.models:
        print("No models loaded! Please run enhanced_train_model.py first.")
        exit(1)
    
    print("Enhanced AI Firewall starting...")
    print(f"Loaded models: {list(firewall.models.keys())}")
    socketio.run(app, host='127.0.0.1', port=5000, debug=True)