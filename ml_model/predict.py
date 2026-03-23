import sys
import json
import numpy as np
import os
import joblib

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf

def main():
    ml_model_dir = os.path.dirname(os.path.abspath(__file__))

    scaler_path = os.path.join(ml_model_dir, "scaler.pkl")
    model_path = os.path.join(ml_model_dir, "autoencoder.keras")

    try:
        scaler = joblib.load(scaler_path)
        autoencoder = tf.keras.models.load_model(model_path)
        
    except Exception as e:
        print(f"CRITICAL: Failed to load models from {ml_model_dir}", file=sys.stderr)
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    THRESHOLD = 0.04

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
            
        try:
            data = json.loads(line)
            flow_id = data.get('flow_id', 'Unknown')
            features = data.get('features', [])
            
            if not features or len(features) != 21:
                continue
                
            X = np.array(features).reshape(1, -1)
            X_scaled = scaler.transform(X)
            X_pred = autoencoder.predict(X_scaled, verbose=0)
            mse = np.mean(np.power(X_scaled - X_pred, 2), axis=1)[0]
            
            status = "Anomaly Detected" if mse > THRESHOLD else "NORMAL"
            print(f"[{status}] (Loss: {mse:.5f}) Flow: {flow_id}")
            sys.stdout.flush()
            
        except Exception as e:
            print(f"ERR: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
