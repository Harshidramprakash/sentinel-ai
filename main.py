import os
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.decomposition import PCA
from flaml import AutoML
from flask import Flask, jsonify, request

app = Flask(__name__, static_folder='frontend')

# 1. REMOVE ALL RANDOMNESS
np.random.seed(42)

# Global objects
scaler = None
pca = None
iso_forest = None
automl = None

MODEL_DIR = "models"
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
IF_PATH = os.path.join(MODEL_DIR, "iso_forest.pkl")
PCA_PATH = os.path.join(MODEL_DIR, "pca.pkl")
AUTOML_PATH = os.path.join(MODEL_DIR, "automl.pkl")

def initialize_models():
    global scaler, pca, iso_forest, automl
    os.makedirs(MODEL_DIR, exist_ok=True)
    
    if os.path.exists(SCALER_PATH) and os.path.exists(IF_PATH) and os.path.exists(PCA_PATH) and os.path.exists(AUTOML_PATH):
        scaler = joblib.load(SCALER_PATH)
        iso_forest = joblib.load(IF_PATH)
        pca = joblib.load(PCA_PATH)
        automl = joblib.load(AUTOML_PATH)
    else:
        df_train = pd.DataFrame({
            "login_attempts": np.random.randint(1, 50, 500),
            "request_rate": np.random.randint(10, 500, 500),
            "time_of_day": np.random.randint(0, 24, 500)
        })
        df_train['request_intensity'] = df_train['request_rate'] / (df_train['login_attempts'] + 1)
        df_train['login_rate_flag'] = (df_train['login_attempts'] > 30).astype(int)
        
        log_cols = ['login_attempts', 'request_rate', 'request_intensity']
        log_features = np.log1p(df_train[log_cols])
        features_to_scale = pd.concat([log_features, df_train[['time_of_day', 'login_rate_flag']]], axis=1)
        
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features_to_scale)
        
        pca = PCA(n_components=2)
        pca_features = pca.fit_transform(scaled_features)
        
        iso_forest = IsolationForest(contamination=0.25, random_state=42)
        iso_forest.fit(pca_features)
        
        joblib.dump(scaler, SCALER_PATH)
        joblib.dump(iso_forest, IF_PATH)
        joblib.dump(pca, PCA_PATH)

        X_syn = np.random.rand(500, 2) * 3
        threats = ['DDoS', 'Brute Force', 'SQL Injection', 'Port Scanning', 'Unusual Access']
        y_syn = np.random.choice(threats, 500)
        
        automl = AutoML()
        automl.fit(X_train=X_syn, y_train=y_syn, task="classification", time_budget=5, verbose=0)
        joblib.dump(automl, AUTOML_PATH)

def generate_dummy_csv(filename="logs.csv"):
    if not os.path.exists(filename):
        data = {
            "ip_address": [f"192.168.1.{i}" for i in range(1, 21)],
            "login_attempts": np.random.randint(1, 50, 20),
            "request_rate": np.random.randint(10, 500, 20)
        }
        pd.DataFrame(data).to_csv(filename, index=False)
    return filename

def preprocessing(df):
    global scaler
    if 'time_of_day' not in df.columns:
        df['time_of_day'] = df.index % 24
    if 'request_intensity' not in df.columns:
        df['request_intensity'] = df['request_rate'] / (df['login_attempts'] + 1)
    if 'login_rate_flag' not in df.columns:
        df['login_rate_flag'] = (df['login_attempts'] > 30).astype(int)
        
    log_cols = ['login_attempts', 'request_rate', 'request_intensity']
    df[log_cols] = df[log_cols].fillna(df[log_cols].mean())
    df.fillna({'time_of_day': 0, 'login_rate_flag': 0}, inplace=True)
    
    log_features = np.log1p(df[log_cols])
    features_to_scale = pd.concat([log_features, df[['time_of_day', 'login_rate_flag']]], axis=1)
    
    scaled_features = scaler.transform(features_to_scale)
    return scaled_features

def detect_anomaly(pca_features):
    global iso_forest
    iso_preds = iso_forest.predict(pca_features)
    n_samples = len(pca_features)
    n_neighbors = min(20, n_samples - 1) if n_samples > 1 else 1
    
    lof = LocalOutlierFactor(n_neighbors=n_neighbors, novelty=False)
    if n_samples > 1:
        lof_preds = lof.fit_predict(pca_features)
    else:
        lof_preds = iso_preds
        
    final_preds = []
    for iso, lof_p in zip(iso_preds, lof_preds):
        if iso == -1 or lof_p == -1:
            final_preds.append(-1)
        else:
            final_preds.append(1)
            
    return np.array(final_preds)

def classify_threat(pca_features):
    global automl
    return automl.predict(pca_features)

def generate_risk_score(anomaly_label, threat_type, request_rate, login_attempts):
    if anomaly_label == 1:
        base = 5 + (request_rate * 0.01) + (login_attempts * 0.02)
    else:
        base = 50 + (request_rate * 0.05) + (login_attempts * 0.1)
        
    severity_map = {
        'DDoS': 25,
        'SQL Injection': 20,
        'Brute Force': 15,
        'Port Scanning': 10,
        'Unusual Access': 8,
        'Normal Activity': 0
    }
    score = base + severity_map.get(threat_type, 0)
    score = int(min(100, max(0, score)))
    
    if score < 30:
        level = 'Low'
    elif score < 60:
        level = 'Medium'
    elif score < 85:
        level = 'High'
    else:
        level = 'Critical'
        
    return score, level

def suggest_action(risk_level):
    actions = {
        'Low': 'Monitor',
        'Medium': 'Log and Alert',
        'High': 'Reset Credentials',
        'Critical': 'Block IP'
    }
    return actions.get(risk_level, 'Monitor')

def process_logs(df):
    global scaler, pca, iso_forest, automl
    
    req_cols = {'ip_address', 'login_attempts', 'request_rate'}
    if not req_cols.issubset(df.columns):
        raise ValueError(f"Missing required columns: {req_cols}")
        
    if scaler is None or pca is None or iso_forest is None or automl is None:
        initialize_models()
        
    scaled_features = preprocessing(df)
    pca_features = pca.transform(scaled_features)
    
    df['Anomaly_Status'] = detect_anomaly(pca_features)
    df['Threat Type'] = classify_threat(pca_features)
    df.loc[df['Anomaly_Status'] == 1, 'Threat Type'] = 'Normal Activity'
    
    risk_scores = []
    risk_levels = []
    actions = []
    
    for anomaly, threat, req_rate, logins in zip(df['Anomaly_Status'], df['Threat Type'], df['request_rate'], df['login_attempts']):
        score, level = generate_risk_score(anomaly, threat, req_rate, logins)
        action = suggest_action(level)
        risk_scores.append(score)
        risk_levels.append(level)
        actions.append(action)
        
    df['Risk Score'] = risk_scores
    df['Risk Level'] = risk_levels
    df['Suggested Action'] = actions
    df['Status'] = ["Normal" if s == 1 else "Anomaly" for s in df['Anomaly_Status']]
    return df

@app.route('/')
def serve_index():
    return app.send_static_file('index.html')

@app.route('/<path:path>')
def serve_static(path):
    return app.send_static_file(path)

@app.route('/api/threats')
def get_threats():
    csv_file = generate_dummy_csv("input_logs.csv")
    df = pd.read_csv(csv_file)
    try:
        df = process_logs(df)
        return jsonify(df.to_dict(orient='records'))
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/upload', methods=['POST'])
def upload_csv():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
        
    if not file.filename.endswith('.csv'):
        return jsonify({"error": "Invalid file format. Please upload a CSV file."}), 400
        
    try:
        df = pd.read_csv(file)
        
        required_columns = {'ip_address', 'login_attempts', 'request_rate'}
        if not required_columns.issubset(df.columns):
            return jsonify({"error": f"CSV must contain the following columns: {', '.join(required_columns)}"}), 400
            
        df_result = process_logs(df)
        return jsonify(df_result.to_dict(orient='records'))
    except Exception as e:
        return jsonify({"error": str(e)}), 400

def main():
    print("[INFO] Initializing Models...")
    initialize_models()
    print("[INFO] Starting Sentinel Web Dashboard...")
    print("[INFO] Navigate to http://127.0.0.1:8080 in your browser.")
    app.run(host='127.0.0.1', port=8080, debug=False)

if __name__ == "__main__":
    main()
