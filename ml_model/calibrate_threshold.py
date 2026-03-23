import argparse
import json
import os
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
import tensorflow as tf


def build_threshold_candidates(mse):
    unique_vals = np.unique(np.sort(mse))
    if len(unique_vals) == 0:
        return np.array([0.0])

    mids = (unique_vals[:-1] + unique_vals[1:]) / 2.0 if len(unique_vals) > 1 else np.array([])
    edge_low = np.array([max(0.0, unique_vals[0] - 1e-12)])
    edge_high = np.array([unique_vals[-1] + 1e-12])
    candidates = np.concatenate([edge_low, unique_vals, mids, edge_high])
    return np.unique(candidates)


def evaluate_threshold(y_true, mse, threshold):
    y_pred = (mse > threshold).astype(int)
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "fpr": float(fpr),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "pred_anomaly_rate": float(np.mean(y_pred)),
    }


def main():
    parser = argparse.ArgumentParser(description="Calibrate anomaly threshold from labeled CSV data.")
    parser.add_argument("csv_path", help="Path to labeled CSV (must contain Label column)")
    parser.add_argument(
        "--config",
        default=os.path.join("..", "cicids2017.json"),
        help="Path to feature config JSON",
    )
    parser.add_argument(
        "--model",
        default="autoencoder.keras",
        help="Path to autoencoder model",
    )
    parser.add_argument(
        "--scaler",
        default="scaler.pkl",
        help="Path to scaler file",
    )
    parser.add_argument(
        "--output",
        default="threshold.json",
        help="Path for output threshold JSON",
    )
    parser.add_argument(
        "--metric",
        choices=["f1", "accuracy"],
        default="f1",
        help="Metric to optimize when selecting threshold",
    )
    parser.add_argument(
        "--evaluate-only",
        action="store_true",
        help="Only print metrics; do not write threshold.json",
    )
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        selected_features = [x.strip() for x in json.load(f)["features"]]

    df = pd.read_csv(args.csv_path)
    df.columns = [c.strip() for c in df.columns]

    missing = [c for c in selected_features if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")
    if "Label" not in df.columns:
        raise ValueError("CSV must contain Label column")

    X = df[selected_features].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    y = np.where(df["Label"].astype(str).str.strip().str.upper().eq("BENIGN"), 0, 1)

    scaler = joblib.load(args.scaler)
    model = tf.keras.models.load_model(args.model)

    X_scaled = scaler.transform(X)
    recon = model.predict(X_scaled, batch_size=4096, verbose=0)
    mse = np.mean(np.power(X_scaled - recon, 2), axis=1)

    candidates = build_threshold_candidates(mse)

    best_threshold = None
    best_score = -1.0
    best_stats = None

    for t in candidates:
        stats = evaluate_threshold(y, mse, float(t))
        score = stats[args.metric]
        # Break ties by preferring lower false positive rate, then higher recall.
        tie_break = (score == best_score and best_stats is not None and (
            stats["fpr"] < best_stats["fpr"] or (
                stats["fpr"] == best_stats["fpr"] and stats["recall"] > best_stats["recall"]
            )
        ))
        if score > best_score or tie_break:
            best_score = score
            best_threshold = float(t)
            best_stats = stats

    legacy_threshold = 0.001201
    legacy_stats = evaluate_threshold(y, mse, legacy_threshold)

    result = {
        "fixed_threshold": best_threshold,
        "metric": args.metric,
        "calibrated_from": os.path.abspath(args.csv_path),
        "rows": int(len(df)),
        "benign_rows": int(np.sum(y == 0)),
        "attack_rows": int(np.sum(y == 1)),
        "selected_features": selected_features,
        "mse": {
            "mean": float(np.mean(mse)),
            "min": float(np.min(mse)),
            "max": float(np.max(mse)),
        },
        "best_stats": best_stats,
        "legacy_threshold": legacy_threshold,
        "legacy_stats": legacy_stats,
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }

    if not args.evaluate_only:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"Saved calibrated threshold to {os.path.abspath(args.output)}")
    else:
        print("Evaluate-only mode: threshold file was not changed.")

    print(f"Selected threshold ({args.metric}): {best_threshold:.6f}")
    print(
        "Best stats: "
        f"acc={best_stats['accuracy']:.6f}, "
        f"prec={best_stats['precision']:.6f}, "
        f"rec={best_stats['recall']:.6f}, "
        f"f1={best_stats['f1']:.6f}, "
        f"fpr={best_stats['fpr']:.6f}"
    )
    print(
        "Legacy 0.001201: "
        f"acc={legacy_stats['accuracy']:.6f}, "
        f"prec={legacy_stats['precision']:.6f}, "
        f"rec={legacy_stats['recall']:.6f}, "
        f"f1={legacy_stats['f1']:.6f}, "
        f"fpr={legacy_stats['fpr']:.6f}"
    )


if __name__ == "__main__":
    main()
