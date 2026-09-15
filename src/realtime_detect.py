import pandas as pd
import joblib
import json
import os
from time import sleep
from sklearn.preprocessing import LabelEncoder

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'rf_model.joblib')
PROTO_ENCODER_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'proto_encoder.joblib')
LABEL_ENCODER_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'label_encoder.joblib')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'model_features.json')
LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.log')
CAPTURE_COLUMNS = [
    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
    'packet_length',
]

def load_models():
    loaded_label_encoder = joblib.load(LABEL_ENCODER_PATH) if os.path.exists(LABEL_ENCODER_PATH) else None
    feature_columns = ['protocol_type', 'src_bytes', 'dst_bytes']
    if os.path.exists(FEATURES_PATH):
        with open(FEATURES_PATH) as stream:
            feature_columns = json.load(stream)
    return (
        joblib.load(MODEL_PATH),
        joblib.load(PROTO_ENCODER_PATH),
        loaded_label_encoder,
        feature_columns,
    )


clf, le_proto, label_le, feature_columns = load_models()
model_mtime = os.path.getmtime(MODEL_PATH)

# Map protocol string to NSL-KDD protocol_type
PROTOCOL_MAP = {'TCP': 'tcp', 'UDP': 'udp', 'ICMP': 'icmp'}

def preprocess_row(row):
    # Map protocol to protocol_type string
    proto_type = PROTOCOL_MAP.get(str(row['protocol']).upper(), 'other')
    if feature_columns == ['protocol_type', 'src_bytes', 'dst_bytes'] and set(le_proto.classes_) == {'tcp', 'udp', 'icmp', 'other'}:
        row['protocol_type'] = {'TCP': 6, 'UDP': 17, 'ICMP': 1}.get(str(row['protocol']).upper(), 0)
    elif pd.api.types.is_numeric_dtype(pd.Series([row['protocol']])):
        row['protocol_type'] = int(row['protocol'])
    else:
        row['protocol_type'] = le_proto.transform([proto_type])[0] if proto_type in le_proto.classes_ else 0
    # Use src_bytes and dst_bytes as packet_length (approximation)
    row['src_bytes'] = int(row['packet_length']) if pd.notnull(row['packet_length']) else 0
    row['dst_bytes'] = 0  # Real-time, we don't know dst_bytes, so set to 0
    for column in feature_columns:
        if column not in row.index:
            row[column] = 0
    return row


def read_capture():
    try:
        frame = pd.read_csv(DATA_PATH)
    except (pd.errors.EmptyDataError, pd.errors.ParserError):
        # The sniffer may be in the middle of appending a CSV row.
        return None
    if 'protocol' not in frame.columns and len(frame.columns) == len(CAPTURE_COLUMNS):
        try:
            frame = pd.read_csv(DATA_PATH, header=None, names=CAPTURE_COLUMNS)
        except (pd.errors.EmptyDataError, pd.errors.ParserError):
            return None
    return frame


def is_suspicious(prediction):
    if label_le is None:
        return prediction != 0
    label = str(label_le.inverse_transform([prediction])[0]).lower()
    return label not in {'normal', 'benign', '0'}

def main():
    print('Starting real-time detection in monitoring mode...')
    last_seen = 0
    while True:
        global clf, le_proto, label_le, feature_columns, model_mtime
        current_model_mtime = os.path.getmtime(MODEL_PATH)
        if current_model_mtime != model_mtime:
            clf, le_proto, label_le, feature_columns = load_models()
            model_mtime = current_model_mtime
            print('Reloaded model trained from the dashboard dataset.')
        if not os.path.exists(DATA_PATH):
            sleep(2)
            continue
        df = read_capture()
        if df is None:
            sleep(1)
            continue
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
        X = new_rows[feature_columns].apply(pd.to_numeric, errors='coerce').fillna(0)
        preds = clf.predict(X)
        for i, pred in enumerate(preds):
            if is_suspicious(pred):
                row = new_rows.iloc[i]
                alert = f"ALERT: Suspicious activity detected: {row.to_dict()} | Predicted label: {pred}"
                print(alert)
                with open(LOG_PATH, 'a') as f:
                    f.write(alert + '\n')
        last_seen = len(df)
        sleep(2)

if __name__ == '__main__':
    main() 