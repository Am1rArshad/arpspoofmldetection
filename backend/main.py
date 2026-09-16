import asyncio
import io
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT_DIR / 'data'
DATA_PATH = DATA_DIR / 'captured_packets.csv'
LOG_PATH = DATA_DIR / 'alerts.log'
STRUCTURED_ALERT_PATH = DATA_DIR / 'alerts.jsonl'
FEEDBACK_PATH = DATA_DIR / 'alert_feedback.jsonl'
UPLOADED_DATA_PATH = DATA_DIR / 'uploaded_dataset.csv'
MODEL_METADATA_PATH = DATA_DIR / 'model_metadata.json'
FRONTEND_DIST = ROOT_DIR / 'frontend' / 'dist'

import sys
sys.path.insert(0, str(ROOT_DIR / 'src'))
from alert_store import read_alerts as read_structured_alerts, write_alerts
from dataset_prep import FEATURES as DATASET_COLUMNS, preprocess as prepare_nsl_kdd
from train_model import FEATURES as MODEL_FEATURES, train_model

DATA_DIR.mkdir(exist_ok=True)


def json_safe(value):
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, np.generic):
        return json_safe(value.item())
    if isinstance(value, (pd.Timestamp, pd.Timedelta)):
        return value.isoformat()
    if isinstance(value, float) and not np.isfinite(value):
        return None
    if isinstance(value, (float, int, str, bool)) or value is None:
        return value
    if hasattr(value, 'item'):
        try:
            return json_safe(value.item())
        except (TypeError, ValueError):
            pass
    if pd.isna(value):
        return None
    return str(value)


def read_packets():
    if not DATA_PATH.exists() or DATA_PATH.stat().st_size == 0:
        return []
    try:
        frame = pd.read_csv(DATA_PATH)
        expected = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_length']
        if not set(expected).issubset(frame.columns):
            frame = pd.read_csv(
                DATA_PATH,
                header=None,
                names=expected,
            )
        frame = frame.loc[:, expected].copy()
        frame = frame.where(pd.notnull(frame), None)
        return [json_safe(record) for record in frame.tail(100).to_dict(orient='records')]
    except (pd.errors.EmptyDataError, pd.errors.ParserError):
        return []


def read_alerts():
    return read_structured_alerts(STRUCTURED_ALERT_PATH)[-10:][::-1]


def read_feedback():
    if not FEEDBACK_PATH.exists():
        return []
    with FEEDBACK_PATH.open() as stream:
        return [json.loads(line) for line in stream if line.strip()]


def read_model_metadata():
    if MODEL_METADATA_PATH.exists():
        try:
            with MODEL_METADATA_PATH.open() as stream:
                return json.load(stream)
        except (OSError, json.JSONDecodeError):
            pass

    if UPLOADED_DATA_PATH.exists() and (DATA_DIR.parent / 'models' / 'rf_model.joblib').exists():
        try:
            frame = pd.read_csv(UPLOADED_DATA_PATH)
            label_encoder = __import__('joblib').load(
                DATA_DIR.parent / 'models' / 'label_encoder.joblib'
            )
            return {
                'source': 'uploaded dataset',
                'filename': UPLOADED_DATA_PATH.name,
                'rows': len(frame),
                'classes': [str(item) for item in label_encoder.classes_],
                'report': 'Existing saved model detected. Retrain to generate a new report.',
                'trained_at': datetime.fromtimestamp(
                    (DATA_DIR.parent / 'models' / 'rf_model.joblib').stat().st_mtime,
                    timezone.utc,
                ).isoformat(),
            }
        except (OSError, ValueError, ImportError):
            pass
    return None


def train_from_frame(frame, source, filename):
    if source == 'uploaded dataset':
        frame.to_csv(UPLOADED_DATA_PATH, index=False)
    report, row_count, classes = train_model(frame)
    result = {
        'source': source,
        'filename': filename,
        'rows': row_count,
        'classes': [str(item) for item in classes],
        'report': report,
        'trained_at': datetime.now(timezone.utc).isoformat(),
    }
    MODEL_METADATA_PATH.write_text(json.dumps(result, indent=2))
    return result


def normalize_uploaded_dataset(frame):
    required = set(MODEL_FEATURES + ['label'])
    if not required.issubset(frame.columns) and len(frame.columns) in {
            len(DATASET_COLUMNS), len(DATASET_COLUMNS) + 1}:
        headerless_columns = DATASET_COLUMNS + (['difficulty']
                                                if len(frame.columns) == len(DATASET_COLUMNS) + 1
                                                else [])
        frame = pd.read_csv(io.BytesIO(frame.to_csv(index=False, header=False).encode()),
                            header=None, names=headerless_columns)
    normalized = {
        column: str(column).strip().lower().replace(' ', '_').replace('-', '_')
        for column in frame.columns
    }
    frame = frame.rename(columns=normalized)
    aliases = {
        'class': 'label', 'target': 'label', 'attack': 'label',
        'attack_type': 'label', 'protocol': 'protocol_type',
        'protocoltype': 'protocol_type', 'srcbytes': 'src_bytes',
        'source_bytes': 'src_bytes', 'src2dst_bytes': 'src_bytes',
        'dstbytes': 'dst_bytes', 'destination_bytes': 'dst_bytes',
        'dst2src_bytes': 'dst_bytes',
    }
    return frame.rename(columns={key: value for key, value in aliases.items()
                                 if key in frame.columns and value not in frame.columns})


@asynccontextmanager
async def lifespan(_app):
    DATA_DIR.mkdir(exist_ok=True)
    yield


app = FastAPI(title='AI-Powered IDS API', version='1.0.0', lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=['http://localhost:5173', 'http://127.0.0.1:5173'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)


@app.get('/api/health')
def health():
    return {'status': 'ok'}


@app.get('/api/traffic')
def traffic():
    packets = read_packets()
    return {'count': len(packets), 'packets': packets}


@app.get('/api/alerts')
def alerts():
    items = read_alerts()
    return {'count': len(items), 'alerts': items}


@app.get('/api/model')
def model_status():
    return read_model_metadata()


@app.post('/api/alerts/{alert_id}/feedback')
def alert_feedback(alert_id: str, feedback: dict):
    label = feedback.get('label')
    if label not in {'threat', 'false_positive'}:
        raise HTTPException(status_code=400, detail='Feedback must be threat or false_positive.')
    alerts = read_structured_alerts(STRUCTURED_ALERT_PATH)
    alert = next((item for item in alerts if item.get('id') == alert_id), None)
    if alert is None:
        raise HTTPException(status_code=404, detail='Alert not found.')
    alert['feedback'] = label
    write_alerts(STRUCTURED_ALERT_PATH, alerts)
    record = {
        'alert_id': alert_id,
        'label': label,
        'features': alert.get('features', {}),
        'created_at': datetime.now(timezone.utc).isoformat(),
    }
    with FEEDBACK_PATH.open('a') as stream:
        stream.write(json.dumps(record) + '\n')
    return alert


@app.get('/api/feedback')
def feedback():
    items = read_feedback()
    return {'count': len(items), 'feedback': items[-100:]}


@app.delete('/api/alerts')
def clear_alerts():
    for path in (LOG_PATH, STRUCTURED_ALERT_PATH, FEEDBACK_PATH):
        if path.exists():
            path.write_text('')
    return {'message': 'Alerts cleared.'}


@app.delete('/api/monitoring-data')
def clear_monitoring_data():
    for path in (LOG_PATH, STRUCTURED_ALERT_PATH, FEEDBACK_PATH, DATA_PATH):
        path.write_text('')
    return {'message': 'Alerts and captured traffic cleared.'}


@app.post('/api/train/nsl-kdd')
async def train_nsl_kdd():
    try:
        return await run_in_threadpool(
            lambda: train_from_frame(
                prepare_nsl_kdd(), 'NSL-KDD', 'NSL-KDD training dataset'
            )
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post('/api/train/upload')
async def train_upload(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith('.csv'):
        raise HTTPException(status_code=400, detail='Please upload a CSV file.')
    try:
        content = await file.read()
        frame = normalize_uploaded_dataset(pd.read_csv(io.BytesIO(content)))
        return await run_in_threadpool(
            lambda: train_from_frame(frame, 'uploaded dataset', file.filename)
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post('/api/train/feedback')
async def train_feedback():
    items = read_feedback()
    if len(items) < 2 or len({item.get('label') for item in items}) < 2:
        raise HTTPException(
            status_code=400,
            detail='Review at least one threat and one false alarm before retraining.',
        )
    frame = pd.DataFrame([
        {**item.get('features', {}), 'label': item['label']}
        for item in items
        if item.get('features') and item.get('label')
    ])
    if frame.empty or frame['label'].nunique() < 2:
        raise HTTPException(
            status_code=400,
            detail='Feedback does not contain enough usable feature data.',
        )
    try:
        return await run_in_threadpool(
            lambda: train_from_frame(frame, 'admin feedback', 'alert_feedback.jsonl')
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.websocket('/ws/alerts')
async def alert_stream(websocket: WebSocket):
    await websocket.accept()
    previous = read_alerts()
    try:
        while True:
            current = read_alerts()
            if current != previous:
                await websocket.send_json({'alerts': current, 'count': len(current)})
                previous = current
            await asyncio.sleep(1)
    except Exception:
        await websocket.close()


if FRONTEND_DIST.exists():
    app.mount('/assets', StaticFiles(directory=FRONTEND_DIST / 'assets'), name='assets')

    @app.get('/{path:path}')
    async def frontend(path: str):
        requested = FRONTEND_DIST / path
        if path and requested.is_file():
            return FileResponse(requested)
        return FileResponse(FRONTEND_DIST / 'index.html')
