import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


def append_alert(path, message, score, kind, features=None):
    alert = {
        'id': uuid.uuid4().hex,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'message': message,
        'score': max(0, min(100, int(score))),
        'kind': kind,
        'features': features or {},
        'feedback': None,
    }
    with Path(path).open('a') as stream:
        stream.write(json.dumps(alert, default=str) + '\n')
    return alert


def read_alerts(path):
    alerts = []
    file_path = Path(path)
    if not file_path.exists():
        return alerts
    with file_path.open() as stream:
        for line in stream:
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(alert, dict) and alert.get('id'):
                alerts.append(alert)
    return alerts


def write_alerts(path, alerts):
    with Path(path).open('w') as stream:
        for alert in alerts:
            stream.write(json.dumps(alert, default=str) + '\n')