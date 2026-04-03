import os
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.decomposition import PCA
from sklearn.tree import DecisionTreeClassifier
from flask import Flask, jsonify, request

app = Flask(__name__, static_folder='frontend')
np.random.seed(42)
scaler = None
pca = None
iso_forest = None
clf = None

MODEL_DIR = "models"
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
IF_PATH = os.path.join(MODEL_DIR, "iso_forest.pkl")
PCA_PATH = os.path.join(MODEL_DIR, "pca.pkl")

def initialize_models(force_retrain=False):
    global scaler, pca, iso_forest
    os.makedirs(MODEL_DIR, exist_ok=True)
    
    if not force_retrain and os.path.exists(SCALER_PATH) and os.path.exists(IF_PATH) and os.path.exists(PCA_PATH):
        try:
            scaler = joblib.load(SCALER_PATH)
            iso_forest = joblib.load(IF_PATH)
            pca = joblib.load(PCA_PATH)
            return
        except Exception:
            pass
            
    df_train = pd.DataFrame({
        "login_attempts": np.random.randint(1, 50, 500),
        "request_rate": np.random.randint(10, 500, 500),
        "time_of_day": np.random.randint(0, 24, 500)
    })
    df_train['request_intensity'] = df_train['request_rate'] / (df_train['login_attempts'] + 1)
    df_train['login_rate_flag'] = (df_train['login_attempts'] > 30).astype(int)
    
    log_cols = ['login_attempts', 'request_rate', 'request_intensity']
    log_features = np.log1p(df_train[log_cols])
    
    features_to_scale = pd.DataFrame({
        'login_attempts': log_features['login_attempts'],
        'request_rate': log_features['request_rate'],
        'request_intensity': log_features['request_intensity'],
        'time_of_day': df_train['time_of_day'],
        'login_rate_flag': df_train['login_rate_flag']
    })
    
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features_to_scale)
    
    pca = PCA(n_components=2)
    pca_features = pca.fit_transform(scaled_features)
    
    iso_forest = IsolationForest(contamination=0.12, random_state=42)
    iso_forest.fit(pca_features)
    
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(iso_forest, IF_PATH)
    joblib.dump(pca, PCA_PATH)

def initialize_classifier():
    global clf
    X_syn = np.random.rand(500, 2)
    threats = ['DDoS', 'Brute Force', 'SQL Injection', 'Port Scanning', 'Unusual Access']
    y_syn = np.random.choice(threats, 500)
    
    clf = DecisionTreeClassifier(random_state=42)
    clf.fit(X_syn, y_syn)

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
    if 'login_attempts' not in df.columns:
        df['login_attempts'] = 0
    if 'request_rate' not in df.columns:
        df['request_rate'] = 0
    if 'time_of_day' not in df.columns:
        df['time_of_day'] = df.index % 24
    if 'request_intensity' not in df.columns:
        df['request_intensity'] = df['request_rate'] / (df['login_attempts'] + 1)
    if 'login_rate_flag' not in df.columns:
        df['login_rate_flag'] = (df['login_attempts'] > 30).astype(int)
        
    log_cols = ['login_attempts', 'request_rate', 'request_intensity']
    df[log_cols] = df[log_cols].fillna(df[log_cols].mean()).fillna(0)
    df.fillna({'time_of_day': 0, 'login_rate_flag': 0}, inplace=True)
    
    log_features = np.log1p(df[log_cols])
    
    features_to_scale = pd.DataFrame({
        'login_attempts': log_features['login_attempts'],
        'request_rate': log_features['request_rate'],
        'request_intensity': log_features['request_intensity'],
        'time_of_day': df['time_of_day'],
        'login_rate_flag': df['login_rate_flag']
    })
    
    scaled_features = scaler.transform(features_to_scale)
    return scaled_features

def detect_anomaly(pca_features):
    global iso_forest
    iso_preds = iso_forest.predict(pca_features)
    n_samples = len(pca_features)
    n_neighbors = min(20, n_samples - 1) if n_samples > 1 else 1
    
    lof = LocalOutlierFactor(n_neighbors=n_neighbors, contamination=0.12, novelty=False)
    if n_samples > 1:
        lof_preds = lof.fit_predict(pca_features)
    else:
        lof_preds = iso_preds
        
    final_preds = []
    for iso, lof_p in zip(iso_preds, lof_preds):
        if iso == -1 and lof_p == -1:
            final_preds.append(-1)
        else:
            final_preds.append(1)
            
    return np.array(final_preds)

def classify_threat(pca_features):
    global clf
    return clf.predict(pca_features)

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
    global scaler, pca, iso_forest, clf
    
    if 'ip_address' not in df.columns:
        df['ip_address'] = 'Unknown'
        
    if scaler is None or pca is None or iso_forest is None or clf is None:
        initialize_models()
        initialize_classifier()
        
    try:
        scaled_features = preprocessing(df)
    except Exception as e:
        print("[INFO] Model schema mismatch detected. Retraining...")
        initialize_models(force_retrain=True)
        scaled_features = preprocessing(df)
        
    try:
        pca_features = pca.transform(scaled_features)
    except Exception:
        print("[INFO] PCA schema mismatch detected. Retraining...")
        initialize_models(force_retrain=True)
        scaled_features = preprocessing(df)
        pca_features = pca.transform(scaled_features)
    
    df['Anomaly_Status'] = detect_anomaly(pca_features)
    preds = classify_threat(pca_features)
    df['Threat Type'] = preds
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
    try:
        df = pd.read_csv(csv_file)
        if df.empty:
            return jsonify([]), 200
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
        if df.empty:
            return jsonify({"error": "Uploaded CSV file is empty"}), 400
            
        df_result = process_logs(df)
        return jsonify(df_result.to_dict(orient='records'))
    except pd.errors.EmptyDataError:
        return jsonify({"error": "Uploaded CSV file is empty"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

def main():
    print("[INFO] Initializing Models...")
    initialize_models()
    initialize_classifier()
    print("[INFO] Starting Sentinel Web Dashboard...")
    print("[INFO] Navigate to http://127.0.0.1:8080 in your browser.")
    app.run(host='127.0.0.1', port=8080, debug=False)

if __name__ == "__main__":
    main()
