import pandas as pd
import joblib
import os
from time import sleep
from sklearn.preprocessing import LabelEncoder
import subprocess
import sys

sys.path.append(os.path.join(os.path.dirname(__file__)))
from threat_intel import check_ip_abuse

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'rf_model.joblib')
PROTO_ENCODER_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'proto_encoder.joblib')
LABEL_ENCODER_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'label_encoder.joblib')
LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.log')
CAPTURE_COLUMNS = [
    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
    'packet_length',
]

ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')

def load_models():
    loaded_label_encoder = joblib.load(LABEL_ENCODER_PATH) if os.path.exists(LABEL_ENCODER_PATH) else None
    return (
        joblib.load(MODEL_PATH),
        joblib.load(PROTO_ENCODER_PATH),
        loaded_label_encoder,
    )


clf, le_proto, label_le = load_models()
model_mtime = os.path.getmtime(MODEL_PATH)

blocked_ips = set()

# Map protocol string to NSL-KDD protocol_type
PROTOCOL_MAP = {'TCP': 'tcp', 'UDP': 'udp', 'ICMP': 'icmp'}

def preprocess_row(row):
    # Map protocol to protocol_type string
    proto_type = PROTOCOL_MAP.get(str(row['protocol']).upper(), 'other')
    row['protocol_type'] = le_proto.transform([proto_type])[0] if proto_type in le_proto.classes_ else 0
    # Use src_bytes and dst_bytes as packet_length (approximation)
    row['src_bytes'] = int(row['packet_length']) if pd.notnull(row['packet_length']) else 0
    row['dst_bytes'] = 0  # Real-time, we don't know dst_bytes, so set to 0
    return row


def is_suspicious(prediction):
    if label_le is None:
        return prediction != 0
    label = str(label_le.inverse_transform([prediction])[0]).lower()
    return label not in {'normal', 'benign', '0'}

def block_ip(ip):
    if ip in blocked_ips:
        return
    try:
        cmd = f'netsh advfirewall firewall add rule name="IDS_Block_{ip}" dir=in action=block remoteip={ip} enable=yes'
        subprocess.run(cmd, shell=True, check=True)
        blocked_ips.add(ip)
        with open(LOG_PATH, 'a') as f:
            f.write(f"AUTO-BLOCKED IP: {ip}\n")
        print(f"AUTO-BLOCKED IP: {ip}")
    except Exception as e:
        with open(LOG_PATH, 'a') as f:
            f.write(f"Failed to block IP {ip}: {e}\n")
        print(f"Failed to block IP {ip}: {e}")

def main():
    print('Starting real-time detection with threat intelligence and auto-blocking...')
    last_seen = 0
    while True:
        global clf, le_proto, label_le, model_mtime
        current_model_mtime = os.path.getmtime(MODEL_PATH)
        if current_model_mtime != model_mtime:
            clf, le_proto, label_le = load_models()
            model_mtime = current_model_mtime
            print('Reloaded model trained from the dashboard dataset.')
        if not os.path.exists(DATA_PATH):
            sleep(2)
            continue
        df = pd.read_csv(DATA_PATH)
        if 'protocol' not in df.columns and len(df.columns) == len(CAPTURE_COLUMNS):
            df = pd.read_csv(DATA_PATH, header=None, names=CAPTURE_COLUMNS)
        if not set(CAPTURE_COLUMNS).issubset(df.columns):
            print('Skipping captured_packets.csv: expected live packet columns were not found.')
            last_seen = len(df)
            sleep(2)
            continue
        if len(df) < last_seen:
            last_seen = 0
        if len(df) == 0 or last_seen >= len(df):
            sleep(2)
            continue
        new_rows = df.iloc[last_seen:]
        new_rows = new_rows.apply(preprocess_row, axis=1)
        X = new_rows[['protocol_type', 'src_bytes', 'dst_bytes']]
        preds = clf.predict(X)
        for i, pred in enumerate(preds):
            if is_suspicious(pred):
                row = new_rows.iloc[i]
                src_ip = row['src_ip']
                alert = f"ALERT: Suspicious activity detected: {row.to_dict()} | Predicted label: {pred}"
                print(alert)
                with open(LOG_PATH, 'a') as f:
                    f.write(alert + '\n')
                # Threat intelligence check
                if ABUSEIPDB_API_KEY:
                    abuse_result = check_ip_abuse(src_ip, ABUSEIPDB_API_KEY)
                    with open(LOG_PATH, 'a') as f:
                        f.write(f"AbuseIPDB: {abuse_result}\n")
                    print(f"AbuseIPDB: {abuse_result}")
                    if abuse_result.get('abuseConfidenceScore', 0) >= 50:
                        block_ip(src_ip)
        last_seen = len(df)
        sleep(2)

if __name__ == '__main__':
    main() 