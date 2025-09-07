from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, emit
import joblib
import numpy as np

app = Flask(__name__)
socketio = SocketIO(app, async_mode='eventlet')

# Load model, scaler, and label encoder
try:
    model = joblib.load('model.pkl')
    scaler = joblib.load('scaler.pkl')
    label_encoder = joblib.load('label_encoder.pkl')
except FileNotFoundError as e:
    print(f"Error: {e}. Ensure 'model.pkl', 'scaler.pkl', and 'label_encoder.pkl' are in the project directory.")
    exit(1)

# Define features (match the dataset used for training)
FEATURES = ['Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Fwd Packet Length Total', 'Protocol']

# Virtual Firewall: Dummy function (real firewall would use iptables)
def virtual_firewall(action):
    return f"Firewall Action: {action.capitalize()}"

# Real-time stats
stats = {'blocked': 0, 'allowed': 0, 'total': 0}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    # Extract and validate features
    try:
        features = []
        for f in FEATURES:
            if f == 'Protocol':
                # Encode categorical Protocol
                protocol_val = data.get(f, 'TCP')  # Default to 'TCP' if missing
                encoded_val = label_encoder.transform([protocol_val])[0]
                features.append(encoded_val)
            else:
                # Numerical features, default to 0 if missing
                features.append(float(data.get(f, 0)))
        features = np.array([features])
    except Exception as e:
        return jsonify({'error': f"Invalid input: {str(e)}"}), 400

    # Scale features and predict
    try:
        features_scaled = scaler.transform(features)
        prediction = model.predict(features_scaled)[0]
    except Exception as e:
        return jsonify({'error': f"Prediction failed: {str(e)}"}), 500

    stats['total'] += 1
    if prediction == 'ATTACK':  # Match dataset label
        stats['blocked'] += 1
        result = {'status': 'blocked', 'type': 'attack'}
        socketio.emit('update', {'stats': stats, 'log': f"Attack detected: Blocked at {stats['total']}"})
        return jsonify({'result': virtual_firewall('block'), **result})
    else:
        stats['allowed'] += 1
        result = {'status': 'allowed', 'type': 'benign'}
        socketio.emit('update', {'stats': stats, 'log': f"Benign traffic: Allowed at {stats['total']}"})
        return jsonify({'result': virtual_firewall('allow'), **result})

if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=5000, debug=True)