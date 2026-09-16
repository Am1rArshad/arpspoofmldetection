import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { Activity, AlertTriangle, Database, Download, Radar, Trash2, Upload } from 'lucide-react';
import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import './styles.css';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

async function request(path, options) {
  const response = await fetch(`${API}${path}`, options);
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail || 'Request failed');
  return body;
}

function App() {
  const [traffic, setTraffic] = useState({ count: 0, packets: [] });
  const [alerts, setAlerts] = useState([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('System ready');
  const [confirmClear, setConfirmClear] = useState(false);
  const [activeView, setActiveView] = useState('telemetry');
  const [trainingResult, setTrainingResult] = useState(null);

  const refresh = async () => {
    const [trafficData, alertData, modelData] = await Promise.all([
      request('/api/traffic'),
      request('/api/alerts'),
      request('/api/model')
    ]);
    setTraffic(trafficData);
    setAlerts((alertData.alerts || []).slice(-10).reverse());
    setTrainingResult(modelData);
  };

  useEffect(() => {
    refresh().catch(error => setMessage(error.message));

    const timer = window.setInterval(() => {
      Promise.all([
        request('/api/traffic'),
        request('/api/alerts')
      ])
        .then(([trafficData, alertData]) => {
          setTraffic(trafficData);
          setAlerts((alertData.alerts || []).slice(-10).reverse());
        })
        .catch(error => setMessage(error.message));
    }, 2000);

    const socket = new WebSocket(`${API.replace(/^http/, 'ws')}/ws/alerts`);
    socket.onmessage = event => {
      const nextAlerts = JSON.parse(event.data).alerts || [];
      setAlerts(nextAlerts.slice(-10).reverse());
    };
    socket.onerror = () => setMessage('Live alert stream unavailable');

    return () => {
      window.clearInterval(timer);
      socket.close();
    };
  }, []);

  const trainNsl = async () => {
    setBusy(true);
    setMessage('Preparing NSL-KDD and training...');
    try {
      const result = await request('/api/train/nsl-kdd', { method: 'POST' });
      setTrainingResult(result);
      setMessage('NSL-KDD model trained successfully');
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  };

  const trainUpload = async event => {
    const file = event.target.files[0];
    if (!file) return;
    setBusy(true);
    setMessage(`Training from ${file.name}...`);
    try {
      const form = new FormData();
      form.append('file', file);
      const result = await request('/api/train/upload', { method: 'POST', body: form });
      setTrainingResult(result);
      setMessage('Uploaded dataset trained successfully');
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
      event.target.value = '';
    }
  };

  const clearAlerts = async () => {
    setBusy(true);
    try {
      await request('/api/alerts', { method: 'DELETE' });
      setAlerts([]);
      setMessage('All alerts cleared');
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  };

  const reviewAlert = async (alert, label) => {
    try {
      const updated = await request(`/api/alerts/${alert.id}/feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label })
      });
      setAlerts(current => current.map(item => item.id === updated.id ? updated : item));
      setMessage(label === 'threat' ? 'Alert marked as a confirmed threat' : 'Alert marked as a false alarm');
    } catch (error) {
      setMessage(error.message);
    }
  };

  const trainFeedback = async () => {
    setBusy(true);
    try {
      const result = await request('/api/train/feedback', { method: 'POST' });
      setTrainingResult(result);
      setMessage('Model retrained from admin feedback');
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  };

  const clearData = async () => {
    setBusy(true);
    try {
      await request('/api/monitoring-data', { method: 'DELETE' });
      await refresh();
      setMessage('Monitoring data cleared');
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
      setConfirmClear(false);
    }
  };

  const recentPackets = (traffic.packets || []).slice(-10).reverse();
  const recentAlerts = (alerts || []).slice(-10).reverse();
  const chartData = recentPackets.map((packet, index) => ({
    index: index + 1,
    bytes: Number(packet.packet_length) || 0
  }));
  const threatChartData = recentAlerts.map((alert, index) => ({
    index: index + 1,
    threatScore: 1,
    label: String(alert).slice(0, 50)
  }));

  const accuracyMatch = trainingResult?.report?.match(/accuracy\s+([0-9.]+)/);
  const accuracy = accuracyMatch ? `${(Number(accuracyMatch[1]) * 100).toFixed(1)}%` : '--';
  const trainedAt = trainingResult?.trained_at
    ? new Date(trainingResult.trained_at).toLocaleString()
    : '--';

  return (
    <main className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark"><Radar size={22} /></span>
          <div><h1>Sentinel IDS</h1></div>
        </div>
        <nav className="topbar-sections" aria-label="Dashboard sections">
          <button className={`topbar-section ${activeView === 'telemetry' ? 'selected' : ''}`} onClick={() => setActiveView('telemetry')}>
            <Activity size={16} />
            <strong>Telemetry</strong>
          </button>
          <button className={`topbar-section ${activeView === 'threat' ? 'selected' : ''}`} onClick={() => setActiveView('threat')}>
            <AlertTriangle size={16} />
            <strong>Threat</strong>
          </button>
          <button className={`topbar-section ${activeView === 'model' ? 'selected' : ''}`} onClick={() => setActiveView('model')}>
            <Database size={16} />
            <strong>Model</strong>
          </button>
          <div className={`topbar-section alert-summary ${recentAlerts.length ? 'has-alerts' : ''}`}>
            <AlertTriangle size={16} />
            <strong>{recentAlerts.length} Alerts</strong>
          </div>
          <div className="status" title={message}><span className="pulse" /></div>
        </nav>
      </header>

      <section className="metrics">
        <article>
          <Activity />
          <span>PACKETS</span>
          <strong>{traffic.count.toLocaleString()}</strong>
        </article>
      </section>

      {activeView === 'telemetry' ? (
        <section className="panel telemetry-view">
          <div className="panel-head">
            <div>
              <p className="eyebrow">TELEMETRY</p>
              <h3>Packet activity</h3>
            </div>
            <span className="live-tag"><span className="pulse" />LIVE</span>
          </div>

          {chartData.length ? (
            <ResponsiveContainer width="100%" height={230}>
              <LineChart data={chartData}>
                <XAxis dataKey="index" hide />
                <YAxis hide />
                <Tooltip contentStyle={{ background: '#14201d', border: '1px solid #355149' }} />
                <Line type="monotone" dataKey="bytes" stroke="#3b82f6" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty">Waiting for packet telemetry...</div>
          )}

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>TIME</th>
                  <th>SOURCE</th>
                  <th>DESTINATION</th>
                  <th>PROTOCOL</th>
                  <th>SIZE</th>
                </tr>
              </thead>
              <tbody>
                {recentPackets.map((packet, index) => (
                  <tr key={`${packet.timestamp ?? 'pkt'}-${index}`}>
                    <td>{packet.timestamp?.slice(11, 19) || '--'}</td>
                    <td>{packet.src_ip || '--'}</td>
                    <td>{packet.dst_ip || '--'}</td>
                    <td>{packet.protocol || '--'}</td>
                    <td>{packet.packet_length || '--'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : activeView === 'threat' ? (
        <section className="panel telemetry-view">
          <div className="panel-head">
            <div>
              <p className="eyebrow">THREAT</p>
              <h3>Threat activity</h3>
            </div>
            <div className="header-actions">
              <span className="count">{recentAlerts.length}</span>
              <button className="ghost small-button" onClick={clearAlerts} disabled={busy || !recentAlerts.length}>
                <Trash2 size={14} />Clear all alerts
              </button>
            </div>
          </div>

          {threatChartData.length ? (
            <ResponsiveContainer width="100%" height={230}>
              <LineChart data={threatChartData}>
                <XAxis dataKey="index" hide />
                <YAxis hide />
                <Tooltip
                  contentStyle={{ background: '#14201d', border: '1px solid #355149' }}
                  formatter={(value) => [`Threat events: ${value}`, 'Alerts']}
                  labelFormatter={(label) => `Alert ${label}`}
                />
                <Line type="monotone" dataKey="threatScore" stroke="#f97316" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty">Waiting for threat telemetry...</div>
          )}

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>TIME</th>
                  <th>SOURCE</th>
                  <th>DESTINATION</th>
                  <th>PROTOCOL</th>
                  <th>SIZE</th>
                </tr>
              </thead>
              <tbody>
                {recentPackets.map((packet, index) => (
                  <tr key={`${packet.timestamp ?? 'pkt'}-${index}`}>
                    <td>{packet.timestamp?.slice(11, 19) || '--'}</td>
                    <td>{packet.src_ip || '--'}</td>
                    <td>{packet.dst_ip || '--'}</td>
                    <td>{packet.protocol || '--'}</td>
                    <td>{packet.packet_length || '--'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="alerts-strip">
            <div className="panel-head compact-head">
              <div>
                <p className="eyebrow">ALERT FEED</p>
                <h3>Recent alerts</h3>
              </div>
            </div>

            <div className="alerts-list">
                {recentAlerts.length ? recentAlerts.map((alert, index) => {
                  const structured = typeof alert === 'object';
                  const message = structured ? alert.message : alert;
                  return (
                    <div className="alert" key={structured ? alert.id : `${alert}-${index}`}>
                      <AlertTriangle size={16} />
                      <div className="alert-content">
                        <span>{message}</span>
                        {structured && (
                          <div className="alert-actions">
                            <strong className="risk-score">RISK {alert.score}/100</strong>
                            <button onClick={() => reviewAlert(alert, 'threat')} disabled={busy || alert.feedback === 'threat'}>Threat</button>
                            <button onClick={() => reviewAlert(alert, 'false_positive')} disabled={busy || alert.feedback === 'false_positive'}>False alarm</button>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                }) : (
                <div className="empty">No suspicious activity detected.</div>
              )}
            </div>
          </div>
        </section>
      ) : (
        <section className="model-view">
          <section className="panel model-controls">
            <div>
              <p className="eyebrow">MODEL CONTROL</p>
              <h3>Train the detector</h3>
              <p className="panel-copy">Upload a labeled CSV or train from the built-in NSL-KDD dataset.</p>
            </div>

            <div className="training-actions">
              <button onClick={trainNsl} disabled={busy}><Download size={16} />Train with NSL-KDD</button>
              <button onClick={trainFeedback} disabled={busy}><Database size={16} />Train from feedback</button>
              <label className="button">
                <Upload size={16} />Upload labeled data
                <input type="file" accept=".csv" onChange={trainUpload} disabled={busy} />
              </label>
              {confirmClear ? (
                <button className="cancel danger" onClick={clearData} disabled={busy}>
                  <Trash2 size={16} />Confirm clear
                </button>
              ) : (
                <button className="cancel ghost" onClick={() => setConfirmClear(true)} disabled={busy}>
                  <Trash2 size={16} />Clear data
                </button>
              )}
            </div>
          </section>

          <section className="panel model-details">
            <div className="panel-head">
              <div>
                <p className="eyebrow">RECENT TRAINING MODEL</p>
                <h3>{trainingResult ? trainingResult.source : 'No training run yet'}</h3>
              </div>
              <span className="model-badge">{busy ? 'TRAINING' : trainingResult ? 'ACTIVE' : 'READY'}</span>
            </div>

            {trainingResult ? (
              <>
                <div className="model-stats">
                  <div><span>ACCURACY</span><strong>{accuracy}</strong></div>
                  <div><span>ROWS</span><strong>{trainingResult.rows.toLocaleString()}</strong></div>
                  <div><span>CLASSES</span><strong>{trainingResult.classes.length}</strong></div>
                </div>
                <div className="class-list">
                    <span>TRAINED FILE</span>
                    <strong>{trainingResult.filename}</strong>
                  </div>
                  <div className="class-list">
                  <span>LABEL CLASSES</span>
                  <strong>{trainingResult.classes.join(', ')}</strong>
                </div>
                  <div className="class-list">
                    <span>LAST TRAINED</span>
                    <strong>{trainedAt}</strong>
                  </div>
                <pre className="report">{trainingResult.report}</pre>
              </>
            ) : (
              <div className="empty model-empty">Train a model to see accuracy, classes, row count, and the classification report.</div>
            )}
          </section>
        </section>
      )}

      <footer>
        <span>Sentinel IDS Dashboard</span>
        <span>{API}</span>
      </footer>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
