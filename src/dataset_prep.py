import pandas as pd
import os
import requests
import zipfile
from io import BytesIO

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
NSL_URL = 'https://github.com/defcom17/NSL_KDD/archive/refs/heads/master.zip'

FEATURES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label'
]  # 42 columns

def download_and_extract():
    print('Downloading NSL-KDD dataset...')
    os.makedirs(DATA_DIR, exist_ok=True)
    r = requests.get(NSL_URL, timeout=60)
    r.raise_for_status()
    z = zipfile.ZipFile(BytesIO(r.content))
    z.extractall(DATA_DIR)
    print('Extracted to', DATA_DIR)

def preprocess():
    kdd_path = os.path.join(DATA_DIR, 'NSL_KDD-master', 'KDDTrain+.txt')
    if not os.path.exists(kdd_path):
        download_and_extract()
    colnames = FEATURES
    df = pd.read_csv(kdd_path, names=colnames, usecols=range(len(colnames)))
    output_path = os.path.join(DATA_DIR, 'nsl_kdd_preprocessed.csv')
    df.to_csv(output_path, index=False)
    print('Preprocessed data saved.')
    return df

if __name__ == '__main__':
    preprocess() 