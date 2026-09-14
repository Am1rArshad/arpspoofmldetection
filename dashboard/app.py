import streamlit as st
import pandas as pd
import os
import sys
import time
from datetime import datetime
import importlib

try:
    st_autorefresh = importlib.import_module('streamlit_autorefresh').st_autorefresh  # pyright: ignore[reportMissingImports]
except ModuleNotFoundError:
    st_autorefresh = None

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from dataset_prep import FEATURES as DATASET_COLUMNS, preprocess as prepare_nsl_kdd
from train_model import FEATURES as MODEL_FEATURES, train_model

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')
LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.log')
UPLOADED_DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'uploaded_dataset.csv')
PREPROCESSED_DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'nsl_kdd_preprocessed.csv')
os.makedirs(os.path.dirname(UPLOADED_DATA_PATH), exist_ok=True)

st.set_page_config(page_title='AI-Powered IDS Dashboard', layout='wide')
st.title('AI-Powered IDS for Home Networks')
if st_autorefresh:
    st_autorefresh(interval=2000, key='ids_dashboard_refresh')
else:
    st.sidebar.info('Install requirements.txt to enable automatic alert updates.')


def prepare_uploaded_dataset(uploaded_file):
    dataset = pd.read_csv(uploaded_file)
    required = set(MODEL_FEATURES + ['label'])

    if not required.issubset(dataset.columns) and len(dataset.columns) in {
            len(DATASET_COLUMNS), len(DATASET_COLUMNS) + 1}:
        uploaded_file.seek(0)
        headerless_columns = DATASET_COLUMNS + (['difficulty']
                                                if len(dataset.columns) == len(DATASET_COLUMNS) + 1
                                                else [])
        dataset = pd.read_csv(uploaded_file, header=None, names=headerless_columns)

    normalized_columns = {
        column: str(column).strip().lower().replace(' ', '_').replace('-', '_')
        for column in dataset.columns
    }
    dataset = dataset.rename(columns=normalized_columns)
    column_aliases = {
        'class': 'label',
        'target': 'label',
        'attack': 'label',
        'attack_type': 'label',
        'labelled': 'label',
        'protocol': 'protocol_type',
        'protocoltype': 'protocol_type',
        'srcbytes': 'src_bytes',
        'source_bytes': 'src_bytes',
        'src2dst_bytes': 'src_bytes',
        'dstbytes': 'dst_bytes',
        'destination_bytes': 'dst_bytes',
        'dst2src_bytes': 'dst_bytes',
    }
    dataset = dataset.rename(columns={key: value for key, value in column_aliases.items()
                                      if key in dataset.columns and value not in dataset.columns})
    return dataset


st.sidebar.header('Train IDS Model')

if st.sidebar.button('Download and train with NSL-KDD', type='primary'):
    try:
        with st.spinner('Downloading and preparing NSL-KDD...'):
            nsl_dataset = prepare_nsl_kdd()
            report, row_count, classes = train_model(nsl_dataset)
        st.session_state['training_source'] = 'NSL-KDD'
        st.session_state['training_result'] = (
            f'Trained on NSL-KDD ({row_count:,} rows). Classes: {", ".join(classes)}\n\n{report}'
        )
        st.rerun()
    except Exception as exc:
        st.sidebar.error(f'Could not train with NSL-KDD: {exc}')

st.sidebar.caption('Or provide your own labeled CSV:')
uploaded_file = st.sidebar.file_uploader('Upload a CSV dataset', type=['csv'])
if uploaded_file:
    try:
        uploaded_dataset = prepare_uploaded_dataset(uploaded_file)
        st.sidebar.caption(f'{len(uploaded_dataset):,} rows loaded')
        if st.sidebar.button('Train IDS model', type='primary'):
            uploaded_dataset.to_csv(UPLOADED_DATA_PATH, index=False)
            report, row_count, classes = train_model(uploaded_dataset)
            st.session_state['training_source'] = 'uploaded dataset'
            st.session_state['training_result'] = (
                f'Trained on {row_count:,} rows. Classes: {", ".join(classes)}\n\n{report}'
            )
            st.rerun()
    except Exception as exc:
        st.sidebar.error(f'Could not prepare dataset: {exc}')

if 'training_result' in st.session_state:
    source = st.session_state.get('training_source', 'the dashboard dataset')
    st.sidebar.success(f'Model trained from {source}.')
    st.sidebar.code(st.session_state['training_result'])

if os.path.exists(PREPROCESSED_DATA_PATH):
    st.sidebar.caption('Prepared NSL-KDD data is saved in data/nsl_kdd_preprocessed.csv.')

def clear_monitoring_data():
    for path in (LOG_PATH, DATA_PATH):
        with open(path, 'w'):
            pass


st.sidebar.header('Monitoring Data')
if st.sidebar.button('Clear alerts and captured traffic', type='secondary'):
    st.session_state['confirm_clear_monitoring_data'] = True

if st.session_state.get('confirm_clear_monitoring_data'):
    st.sidebar.warning('This will delete all current alerts and captured traffic.')
    confirm_clear = st.sidebar.button('Confirm clear', type='primary')
    cancel_clear = st.sidebar.button('Cancel')
    if cancel_clear:
        st.session_state['confirm_clear_monitoring_data'] = False
        st.rerun()
    if confirm_clear:
        try:
            clear_monitoring_data()
            st.session_state['confirm_clear_monitoring_data'] = False
            st.sidebar.success('Alerts and captured traffic cleared.')
            st.rerun()
        except OSError as exc:
            st.sidebar.error(f'Could not clear monitoring data: {exc}')

# Live traffic stats
def load_packets():
    if os.path.exists(DATA_PATH):
        try:
            return pd.read_csv(DATA_PATH)
        except (pd.errors.EmptyDataError, pd.errors.ParserError):
            return pd.DataFrame()
    return pd.DataFrame()

def load_alerts():
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH) as f:
            lines = f.readlines()
        return lines[-20:][::-1]  # Show last 20 alerts, newest first
    return []

packets = load_packets()
col1, col2 = st.columns(2)

with col1:
    st.header('Live Traffic')
    st.write(f"Total packets captured: {len(packets)}")
    if not packets.empty:
        st.dataframe(packets.tail(20))
        if 'packet_length' in packets.columns:
            st.line_chart(packets['packet_length'].tail(100))
        else:
            st.info('Packet-size chart is unavailable because the captured data has no packet_length column.')

with col2:
    st.header('Recent Alerts')
    alerts = load_alerts()
    if alerts:
        for alert in alerts:
            st.error(alert.strip())
    else:
        st.success('No suspicious activity detected.')

# Sidebar: Threat Intelligence (AbuseIPDB)
st.sidebar.header('Threat Intelligence (AbuseIPDB)')
last_abuse = None
for line in alerts:
    if line.startswith('AbuseIPDB:'):
        try:
            import ast
            abuse_data = ast.literal_eval(line[len('AbuseIPDB: '):].strip())
            last_abuse = abuse_data
            break
        except Exception:
            continue
if last_abuse:
    st.sidebar.write(f"**IP:** {last_abuse.get('ip')}")
    st.sidebar.write(f"**Abuse Score:** {last_abuse.get('abuseConfidenceScore')}")
    st.sidebar.write(f"**Country:** {last_abuse.get('countryCode')}")
    st.sidebar.write(f"**Usage:** {last_abuse.get('usageType')}")
    st.sidebar.write(f"**Domain:** {last_abuse.get('domain')}")
    st.sidebar.write(f"**Total Reports:** {last_abuse.get('totalReports')}")
    st.sidebar.write(f"**Last Reported:** {last_abuse.get('lastReportedAt')}")
    if last_abuse.get('abuseConfidenceScore', 0) >= 50:
        st.sidebar.error('This IP was auto-blocked!')
else:
    st.sidebar.info('No recent AbuseIPDB results.')

# Optionally, show GeoIP info for suspicious IPs
try:
    import geoip2.database
    GEOIP_DB = os.path.join(os.path.dirname(__file__), '..', 'data', 'GeoLite2-City.mmdb')
    if os.path.exists(GEOIP_DB) and not packets.empty:
        st.header('GeoIP Lookup (last suspicious IP)')
        last_alert = alerts[0] if alerts else None
        if last_alert:
            import re
            import ast
            match = re.search(r"src_ip': '([^']+)'", last_alert)
            if match:
                ip = match.group(1)
                reader = geoip2.database.Reader(GEOIP_DB)
                try:
                    response = reader.city(ip)
                    st.write(f"IP: {ip}")
                    st.write(f"Country: {response.country.name}")
                    st.write(f"City: {response.city.name}")
                except Exception as e:
                    st.write(f"GeoIP lookup failed: {e}")
                reader.close()
except ImportError:
    pass

st.caption('AI-Powered IDS | Streamlit Dashboard') 