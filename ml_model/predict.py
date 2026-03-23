import sys
import json
import numpy as np
import os
import joblib

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf


def _get_env_float(name, default):
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _get_env_int(name, default):
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _get_env_bool(name, default):
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_env_ratio(name, default):
    return min(max(_get_env_float(name, default), 0.0), 1.0)


def _load_threshold_from_file(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        value = data.get("fixed_threshold")
        if value is None:
            return None
        return float(value)
    except Exception:
        return None

def main():
    ml_model_dir = os.path.dirname(os.path.abspath(__file__))

    scaler_path = os.path.join(ml_model_dir, "scaler.pkl")
    model_path = os.path.join(ml_model_dir, "autoencoder.keras")
    threshold_path = os.path.join(ml_model_dir, "threshold.json")

    try:
        scaler = joblib.load(scaler_path)
        autoencoder = tf.keras.models.load_model(model_path)
        
    except Exception as e:
        print(f"CRITICAL: Failed to load models from {ml_model_dir}", file=sys.stderr)
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    default_threshold = 0.02
    file_threshold = _load_threshold_from_file(threshold_path)

    if os.getenv("AVADUMP_THRESHOLD") is not None:
        fixed_threshold = _get_env_float("AVADUMP_THRESHOLD", default_threshold)
        threshold_source = "env"
    elif file_threshold is not None:
        fixed_threshold = file_threshold
        threshold_source = "threshold.json"
    else:
        fixed_threshold = default_threshold
        threshold_source = "builtin-default"

    use_adaptive_threshold = _get_env_bool("AVADUMP_ADAPTIVE_THRESHOLD", False)
    warmup_flows = max(0, _get_env_int("AVADUMP_THRESHOLD_WARMUP", 10))
    quantile_window = max(10, _get_env_int("AVADUMP_THRESHOLD_WINDOW", 2000))
    quantile_level = min(max(_get_env_float("AVADUMP_THRESHOLD_QUANTILE", 0.995), 0.5), 0.9999)

    ood_checks_enabled = _get_env_bool("AVADUMP_OOD_CHECK", True)
    ood_abs_z_max = max(0.5, _get_env_float("AVADUMP_OOD_ABS_Z_MAX", 8.0))
    ood_frac_threshold = _get_env_ratio("AVADUMP_OOD_FEATURE_FRAC", 0.25)
    ood_warn_every = max(1, _get_env_int("AVADUMP_OOD_WARN_EVERY", 100))

    mse_history = []

    print(
        (
            "Predictor config: "
            f"fixed_threshold={fixed_threshold:.6f}, "
            f"threshold_source={threshold_source}, "
            f"adaptive={use_adaptive_threshold}, "
            f"warmup={warmup_flows}, "
            f"window={quantile_window}, "
            f"quantile={quantile_level:.4f}, "
            f"ood_check={ood_checks_enabled}, "
            f"ood_abs_z_max={ood_abs_z_max:.2f}, "
            f"ood_feature_frac={ood_frac_threshold:.2f}"
        ),
        file=sys.stderr,
    )

    flow_count = 0
    ood_count = 0

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

            flow_count += 1
            if ood_checks_enabled:
                invalid_values = not np.isfinite(X_scaled).all()
                abs_scaled = np.abs(X_scaled)
                exceed_frac = float(np.mean(abs_scaled > ood_abs_z_max))
                looks_ood = invalid_values or exceed_frac >= ood_frac_threshold
                if looks_ood:
                    ood_count += 1
                    if ood_count <= 5 or ood_count % ood_warn_every == 0:
                        max_abs_z = float(np.max(abs_scaled)) if np.size(abs_scaled) else 0.0
                        print(
                            (
                                "WARN: Possible preprocessing/model mismatch or out-of-distribution flow "
                                f"flow_id={flow_id} "
                                f"invalid_values={invalid_values} "
                                f"exceed_frac={exceed_frac:.3f} "
                                f"max_abs_z={max_abs_z:.2f} "
                                f"ood_count={ood_count}/{flow_count}"
                            ),
                            file=sys.stderr,
                        )

            X_pred = autoencoder.predict(X_scaled, verbose=0)
            mse = np.mean(np.power(X_scaled - X_pred, 2), axis=1)[0]

            effective_threshold = fixed_threshold
            if use_adaptive_threshold and len(mse_history) >= warmup_flows:
                recent = np.array(mse_history[-quantile_window:])
                dynamic_threshold = float(np.quantile(recent, quantile_level))
                effective_threshold = max(fixed_threshold, dynamic_threshold)
            
            status = "Anomaly Detected" if mse > effective_threshold else "NORMAL"
            print(
                f"[{status}] (Loss: {mse:.5f}, Threshold: {effective_threshold:.5f}) Flow: {flow_id}"
            )
            sys.stdout.flush()

            # Learn adaptive baseline only from low-loss candidate-normal flows.
            if mse <= fixed_threshold:
                mse_history.append(float(mse))
                if len(mse_history) > quantile_window * 2:
                    mse_history = mse_history[-quantile_window:]
            
        except Exception as e:
            print(f"ERR: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
