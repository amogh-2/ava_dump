import sys
import json
import numpy as np
import os
import joblib
import warnings
import logging

os.environ['ABSL_MIN_LOG_LEVEL'] = '3'
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf

warnings.filterwarnings(
    "ignore",
    category=UserWarning,
    message=r"X does not have valid feature names, but StandardScaler was fitted with feature names",
)
warnings.filterwarnings(
    "ignore",
    category=UserWarning,
    message=r".*InconsistentVersionWarning.*",
)

try:
    from sklearn.exceptions import InconsistentVersionWarning

    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except Exception:
    pass

tf.get_logger().setLevel(logging.ERROR)

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

    THRESHOLD = 0.001201

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
                
            X = np.array(features, dtype=np.float64).reshape(1, -1)
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
