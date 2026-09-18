"""
SentinelFlow NIDS — Professional Flask Backend
Run: python app.py
Then open: http://localhost:5000
"""

import os
import sys
import json
import time
import random
import io
from datetime import datetime

import joblib
import pandas as pd
from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    stream_with_context,
    send_file,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "src"))

try:
    from preprocess import (
        load_raw,
        add_binary_and_category_labels,
        encode_categorical,
        get_features_and_target,
    )
    PREPROCESS_AVAILABLE = True
except ImportError:
    PREPROCESS_AVAILABLE = False
    print("[WARN] src/preprocess.py not found. Running in demo mode.")

MODEL_PATH = os.path.join(BASE_DIR, "models", "rf_model.joblib")
ENCODERS_PATH = os.path.join(BASE_DIR, "models", "encoders.joblib")

NSL_KDD_FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]
NSL_KDD_FULL = NSL_KDD_FEATURES + ["label", "difficulty_level"]

app = Flask(__name__)

model = None
encoders = None
X_TEST = None
Y_TEST = None
test_df = None
FEATURE_COLUMNS = []
MODEL_INFO = {
    "model_type": "—",
    "dataset": "NSL-KDD",
    "n_estimators": None,
    "attack_precision": 0.9677,
    "attack_recall": 0.6370,
    "status": "not_loaded",
}

print("=" * 60)
print("  SentinelFlow NIDS — starting up")
print("=" * 60)

if os.path.exists(MODEL_PATH) and os.path.exists(ENCODERS_PATH) and PREPROCESS_AVAILABLE:
    try:
        print("[+] Loading model...")
        model = joblib.load(MODEL_PATH)
        encoders = joblib.load(ENCODERS_PATH)

        print("[+] Loading NSL-KDD reference data...")
        train_df = add_binary_and_category_labels(load_raw("train"))
        test_df = add_binary_and_category_labels(load_raw("test"))
        train_enc, test_enc, _ = encode_categorical(train_df, test_df)
        X_TEST, Y_TEST = get_features_and_target(test_enc, target_col="is_attack")
        FEATURE_COLUMNS = list(X_TEST.columns)

        MODEL_INFO.update({
            "model_type": type(model).__name__,
            "n_estimators": getattr(model, "n_estimators", None),
            "status": "loaded",
        })
        print(f"[+] Ready. {len(X_TEST):,} test records | {len(FEATURE_COLUMNS)} features")
    except Exception as e:
        print(f"[!] Failed to load model/data: {e}")
        MODEL_INFO["status"] = f"error: {e}"
else:
    print("[!] Model or preprocess missing — running in demo mode.")

ALERTS_LOG = []
MAX_ALERTS = 500
LAST_CSV_RESULTS = None


def simulated_ip():
    return f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"


def record_alert(origin, category, confidence):
    confidence = float(confidence)
    alert = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "date": datetime.now().strftime("%Y-%m-%d"),
        "source_ip": simulated_ip(),
        "dest_ip": simulated_ip(),
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "dest_port": random.choice([80, 443, 21, 22, 3389, 8080, 53]),
        "type": category if category and str(category).lower() != "normal" else "Unknown",
        "confidence": round(confidence * 100, 1),
        "severity": "High" if confidence > 0.85 else ("Medium" if confidence > 0.6 else "Low"),
        "origin": origin,
        "simulated": True,
    }
    ALERTS_LOG.insert(0, alert)
    if len(ALERTS_LOG) > MAX_ALERTS:
        ALERTS_LOG.pop()
    return alert


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/overview")
def overview():
    if X_TEST is not None and Y_TEST is not None:
        return jsonify({
            "total_records": int(len(X_TEST)),
            "attacks": int(Y_TEST.sum()),
            "normal": int((Y_TEST == 0).sum()),
            "attack_precision": MODEL_INFO["attack_precision"],
            "attack_recall": MODEL_INFO["attack_recall"],
            "false_negative_rate": round(1 - MODEL_INFO["attack_recall"], 4),
            "model_status": MODEL_INFO["status"],
            "alerts_logged": len(ALERTS_LOG),
        })
    return jsonify({
        "total_records": 22544,
        "attacks": 12833,
        "normal": 9711,
        "attack_precision": MODEL_INFO["attack_precision"],
        "attack_recall": MODEL_INFO["attack_recall"],
        "false_negative_rate": round(1 - MODEL_INFO["attack_recall"], 4),
        "model_status": MODEL_INFO["status"],
        "alerts_logged": len(ALERTS_LOG),
    })


@app.route("/api/model-info")
def model_info():
    return jsonify(MODEL_INFO)


@app.route("/api/distribution")
def distribution():
    if test_df is not None and "attack_category" in test_df.columns:
        cat_counts = test_df["attack_category"].value_counts()
        is_attack_counts = test_df["is_attack"].map({0: "Normal", 1: "Attack"}).value_counts()
        return jsonify({
            "categories": {
                "labels": cat_counts.index.tolist(),
                "values": [int(v) for v in cat_counts.values],
            },
            "split": {
                "labels": is_attack_counts.index.tolist(),
                "values": [int(v) for v in is_attack_counts.values],
            },
        })
    return jsonify({
        "categories": {
            "labels": ["normal", "DoS", "Probe", "R2L", "U2R"],
            "values": [9711, 7458, 2421, 2754, 200],
        },
        "split": {
            "labels": ["Normal", "Attack"],
            "values": [9711, 12833],
        },
    })


@app.route("/api/alerts")
def alerts():
    return jsonify(ALERTS_LOG[:150])


@app.route("/api/simulate")
def simulate():
    try:
        n_packets = max(5, min(int(request.args.get("n", 50)), 300))
    except (ValueError, TypeError):
        n_packets = 50

    def generate():
        if model is None or X_TEST is None:
            for i in range(1, n_packets + 1):
                is_attack = random.random() < 0.35
                proba = round(random.uniform(0.75, 0.99) if is_attack else random.uniform(0.01, 0.25), 4)
                payload = {
                    "packet": i,
                    "total": n_packets,
                    "is_attack": is_attack,
                    "probability": proba,
                    "true_label": "Attack" if is_attack else "Normal",
                    "alert_count": 0,
                }
                if is_attack:
                    alert = record_alert("Live Monitor", random.choice(["DoS", "Probe", "R2L", "U2R"]), proba)
                    payload["alert"] = alert
                    payload["alert_count"] = sum(1 for a in ALERTS_LOG if a["origin"] == "Live Monitor")
                yield f"data: {json.dumps(payload)}\n\n"
                time.sleep(0.11)
            yield f"data: {json.dumps({'done': True, 'inspected': n_packets, 'alerts': payload.get('alert_count', 0)})}\n\n"
            return

        sample_idx = X_TEST.sample(n=min(n_packets, len(X_TEST))).index
        sample = X_TEST.loc[sample_idx].reset_index(drop=True)
        true_vals = Y_TEST.loc[sample_idx].reset_index(drop=True)
        categories = test_df.loc[sample_idx, "attack_category"].reset_index(drop=True)

        alert_count = 0
        for i in range(len(sample)):
            row = sample.iloc[[i]]
            pred = int(model.predict(row)[0])
            proba = float(model.predict_proba(row)[0][1])
            payload = {
                "packet": i + 1,
                "total": len(sample),
                "is_attack": bool(pred == 1),
                "probability": proba,
                "true_label": "Attack" if int(true_vals.iloc[i]) == 1 else "Normal",
                "alert_count": alert_count,
            }
            if pred == 1:
                alert_count += 1
                payload["alert_count"] = alert_count
                cat = categories.iloc[i] if categories.iloc[i] != "normal" else "Unknown"
                payload["alert"] = record_alert("Live Monitor", str(cat), proba)

            yield f"data: {json.dumps(payload)}\n\n"
            time.sleep(0.11)

        yield f"data: {json.dumps({'done': True, 'inspected': len(sample), 'alerts': alert_count})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/analyze-csv", methods=["POST"])
def analyze_csv():
    global LAST_CSV_RESULTS

    if model is None or not FEATURE_COLUMNS:
        return jsonify({
            "error": "Model not loaded. Place rf_model.joblib and encoders.joblib in models/."
        }), 503

    file = request.files.get("file")
    if file is None:
        return jsonify({"error": "No file uploaded."}), 400

    try:
        raw = pd.read_csv(file, header=None)
    except Exception as e:
        return jsonify({"error": f"Could not parse CSV: {e}"}), 400

    n_cols = raw.shape[1]
    if n_cols == len(NSL_KDD_FEATURES):
        raw.columns = NSL_KDD_FEATURES
    elif n_cols == len(NSL_KDD_FEATURES) + 1:
        raw.columns = NSL_KDD_FEATURES + ["label"]
    elif n_cols == len(NSL_KDD_FULL):
        raw.columns = NSL_KDD_FULL
    else:
        return jsonify({
            "error": f"Expected {len(NSL_KDD_FEATURES)} feature columns. Got {n_cols}."
        }), 400

    try:
        train_df_local = add_binary_and_category_labels(load_raw("train"))
        _, uploaded_enc, _ = encode_categorical(train_df_local, raw)
        X_new = uploaded_enc[FEATURE_COLUMNS]
    except Exception as e:
        return jsonify({"error": f"Preprocessing failed: {e}"}), 400

    preds = model.predict(X_new)
    probas = model.predict_proba(X_new)[:, 1]

    results = []
    attack_count = 0
    for i in range(len(X_new)):
        is_attack = bool(preds[i] == 1)
        if is_attack:
            attack_count += 1
            record_alert("CSV Analysis", "Unknown", float(probas[i]))
        results.append({
            "row": i + 1,
            "is_attack": is_attack,
            "probability": round(float(probas[i]) * 100, 1),
        })

    out_df = raw.copy()
    out_df["prediction"] = ["Attack" if p == 1 else "Normal" for p in preds]
    out_df["attack_probability"] = [round(float(p) * 100, 2) for p in probas]
    LAST_CSV_RESULTS = out_df

    return jsonify({
        "rows": results[:1000],
        "summary": {
            "total_rows": len(X_new),
            "attacks": attack_count,
            "normal": len(X_new) - attack_count,
        },
    })


@app.route("/api/download-results")
def download_results():
    if LAST_CSV_RESULTS is None:
        return jsonify({"error": "No analysis results available."}), 404
    buf = io.StringIO()
    LAST_CSV_RESULTS.to_csv(buf, index=False)
    mem = io.BytesIO(buf.getvalue().encode("utf-8"))
    return send_file(
        mem,
        mimetype="text/csv",
        as_attachment=True,
        download_name="sentinelflow_results.csv",
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n[+] SentinelFlow running at http://localhost:{port}")
    print("    Press Ctrl+C to stop.\n")
    app.run(host="0.0.0.0", port=port, debug=True)