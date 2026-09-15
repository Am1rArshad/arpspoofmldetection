# AI-Powered IDS for Home Networks

This project is a real-time intrusion detection system for home or lab networks.
It combines Scapy packet capture, a Random Forest classifier, ARP spoofing
detection, and a React/Vite dashboard.

## Features
- Live IP packet capture with Scapy.
- Random Forest training from NSL-KDD or an uploaded labeled CSV.
- Custom dataset support, including `normal` and `arp_spoofing` labels.
- ARP IP-to-MAC consistency checks for direct spoofing alerts.
- React/Vite dashboard for traffic, alerts, and model status.
- Persistent models in `models/` and training metadata in
     `data/model_metadata.json`.
- Optional AbuseIPDB threat intelligence.

## Project Structure
```text
backend/       FastAPI API and WebSocket alert stream
frontend/      React/Vite dashboard
src/           Packet capture, training, detection, and threat intelligence
data/          Datasets, captured packets, alerts, and model metadata
models/        Saved model and encoders
run_local.sh   Local service launcher with clean restart
requirements.txt
```

## Quickstart on Linux
### 1. Clone the repository

Replace the placeholder URL with the actual repository URL:
```sh
git clone https://github.com/<owner>/<repository>.git
cd ai-powered-ids-for-home-networks-main
```

### 2. Install Python dependencies
```sh
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Install and build the Vite frontend
```sh
cd frontend
npm install
npm run build
cd ..
```

The build creates `frontend/dist`. For development, `run_local.sh` starts the
Vite development server on port 5173.

### 4. Start the IDS
Set the interface used by the packet sniffer. Replace `ens33` with the interface
shown by `ip -br addr` on your machine:

```sh
source venv/bin/activate
export IDS_SNIFF_INTERFACE=ens33
./run_local.sh
```

Open the dashboard at <http://localhost:5173>. The API documentation is at
<http://localhost:8000/docs>.

The launcher automatically stops old processes, frees ports 8000 and 5173, and
starts the backend, frontend, packet capture, and real-time detector. Press
`Ctrl+C` to stop all services.

On Linux, packet capture requires root or passwordless sudo. Without capture
permissions, the dashboard still starts but live detection cannot work.

## Upload a Dataset and Train
1. Open the dashboard and select **Model**.
2. Select **Upload labeled data**.
3. Choose a CSV containing a `label` column with at least two classes.
4. Wait for training to finish.

The included custom dataset has 74,343 flow records with `normal` and
`arp_spoofing` labels. Numeric flow columns such as `protocol_type`, `src_bytes`,
and `dst_bytes` are used for live-compatible training. The trained model is
saved under `models/`, and the dashboard remembers the filename, classes, row
count, report, and training time after refresh or restart.

The built-in NSL-KDD dataset can be trained with **Train with NSL-KDD**.
To retrain from the existing uploaded dataset without using the dashboard:

```sh
venv/bin/python - <<'PY'
import pandas as pd
from backend.main import train_from_frame

result = train_from_frame(
     pd.read_csv('data/uploaded_dataset.csv'),
     'uploaded dataset',
     'uploaded_dataset.csv',
)
print(result['report'])
PY
```

## Verify Capture and Alerts
In another terminal:

```sh
tail -f data/captured_packets.csv
tail -f data/alerts.log
```

For PC A attacking PC B while PC C runs the IDS, PC C must be able to see the
traffic. Use a gateway, bridge, switch port mirror, or capture directly on the
network path. A normal switched network does not send PC A-to-PC B unicast
traffic to an unrelated PC C.

ARP spoofing alerts are generated when the same IP address is observed with
different MAC addresses. This requires the sniffer to capture ARP packets on
the monitored network.

## Clean Restart
`run_local.sh` performs this cleanup automatically. If services were started
manually, use:

```sh
fuser -k 8000/tcp 5173/tcp 2>/dev/null || true
pkill -f 'sniffer.py' 2>/dev/null || true
pkill -f 'realtime_detect.py' 2>/dev/null || true
./run_local.sh
```

## Optional AbuseIPDB Configuration
```sh
export ABUSEIPDB_API_KEY="your_api_key_here"
```

## Troubleshooting
- **Packet capture skipped:** Check `IDS_SNIFF_INTERFACE`, then run with the
     required privileges or configure passwordless sudo.
- **No alerts:** Confirm that `data/captured_packets.csv` is growing and that
     PC C can see the traffic.
- **No ARP alert:** Confirm that ARP packets are visible and that the same IP is
     being advertised by different MAC addresses.
- **Model cannot be saved:** Repair ownership once with:

     ```sh
     sudo chown -R "$USER":"$(id -gn)" models data
     ```

- **Dashboard unavailable:** Check that ports 5173 and 8000 are free and rerun
     `./run_local.sh`.

## Docker
```sh
docker build -t ai-ids .
docker run --rm -it --net=host --cap-add=NET_RAW \
     -v "$(pwd)/data:/app/data" ai-ids
```

Use only on networks you own or are authorized to monitor.
# AI-Powered IDS for Home Networks

This project is a real-time intrusion detection system for home or lab networks.
It combines Scapy packet capture, a Random Forest classifier, ARP spoofing
detection, and a React/Vite dashboard.

## Features

- Live packet capture with Scapy.
- Random Forest training from NSL-KDD or an uploaded labeled CSV.
- Custom dataset support, including `normal` and `arp_spoofing` labels.
- ARP IP-to-MAC consistency checks for direct spoofing alerts.
- React/Vite dashboard for traffic, alerts, and saved model details.
- Persistent models in `models/` and metadata in `data/model_metadata.json`.

## Quickstart on Linux

### 1. Clone the repository

```sh
git clone https://github.com/<owner>/<repository>.git
cd ai-powered-ids-for-home-networks-main
```

### 2. Install Python dependencies

```sh
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Install and build the Vite frontend

```sh
cd frontend
npm install
npm run build
cd ..
```

### 4. Start the IDS

Find the capture interface with `ip -br addr`, then replace `ens33` below if
needed:

```sh
source venv/bin/activate
export IDS_SNIFF_INTERFACE=ens33
./run_local.sh
```

Open the dashboard at <http://localhost:5173>. The API documentation is at
<http://localhost:8000/docs>. The launcher cleans old processes and starts the
backend, frontend, packet capture, and detector. Press `Ctrl+C` to stop them.

Linux packet capture requires root or passwordless sudo. Without capture
permissions, the dashboard starts but live detection cannot work.

## Upload a Dataset and Train

1. Open the dashboard and select **Model**.
2. Select **Upload labeled data**.
3. Choose a CSV containing a `label` column with at least two classes.
4. Wait for training to finish.

The included custom dataset has `normal` and `arp_spoofing` labels. Numeric flow
columns such as `protocol_type`, `src_bytes`, and `dst_bytes` are used for
live-compatible training. The trained model is saved under `models/`, and the
dashboard restores its filename, classes, row count, report, and training time
after refresh or restart.

The built-in NSL-KDD dataset can also be trained with **Train with NSL-KDD**.

## Verify Capture and Alerts

```sh
tail -f data/captured_packets.csv
tail -f data/alerts.log
```

For PC A attacking PC B while PC C runs the IDS, PC C must be able to see the
traffic. Use a gateway, bridge, switch port mirror, or capture directly on the
network path. A normal switched network does not send PC A-to-PC B unicast
traffic to an unrelated PC C.

ARP alerts are generated when the same IP address is observed with different MAC
addresses. The sniffer must capture ARP packets on the monitored network.

## Clean Restart

`run_local.sh` performs cleanup automatically. For services started manually:

```sh
fuser -k 8000/tcp 5173/tcp 2>/dev/null || true
pkill -f 'sniffer.py' 2>/dev/null || true
pkill -f 'realtime_detect.py' 2>/dev/null || true
./run_local.sh
```

## Optional AbuseIPDB Configuration

```sh
export ABUSEIPDB_API_KEY="your_api_key_here"
```

## Troubleshooting

- **Packet capture skipped:** Check `IDS_SNIFF_INTERFACE` and configure the
     required Linux permissions.
- **No alerts:** Confirm `data/captured_packets.csv` is growing and PC C can see
     the traffic.
- **No ARP alert:** Confirm ARP packets are visible and an IP is being advertised
     by different MAC addresses.
- **Model cannot be saved:** Run
     `sudo chown -R "$USER":"$(id -gn)" models data` once.
- **Dashboard unavailable:** Check ports 5173 and 8000, then rerun
     `./run_local.sh`.

## Docker

```sh
docker build -t ai-ids .
docker run --rm -it --net=host --cap-add=NET_RAW \
     -v "$(pwd)/data:/app/data" ai-ids
```

Use only on networks you own or are authorized to monitor.

<!--

## 🚀 Overview
This project is a lightweight, AI-enhanced Intrusion Detection System (IDS) designed to monitor network traffic on your home Wi-Fi network. It uses machine learning to flag unusual or potentially malicious activity in real time, with a modern dashboard and optional threat intelligence and auto-blocking features.

<img width="2527" height="1280" alt="Screenshot 2025-07-16 211455" src="https://github.com/user-attachments/assets/91966419-ac9c-494f-a5a5-2852607e292c" />

---

## 🧰 Features
- **Real-time Packet Sniffing:** Captures live network traffic using Scapy.
- **Feature Extraction:** Extracts protocol, source/destination, and packet size features.
- **Machine Learning Detection:** Classifies traffic as normal or suspicious using a Random Forest model.
- **Threat Intelligence:** Integrates with AbuseIPDB to check IP reputation.
- **Auto-Blocking:** Automatically blocks high-risk IPs using firewall rules (Windows only).
- **Interactive Dashboard:** Streamlit dashboard for live traffic, alerts, and threat intelligence.
- **Dockerized:** Easy deployment with Docker.

---

## 🏗️ Architecture
```
+-------------------+      +-------------------+      +-------------------+
|  Packet Sniffer   | ---> |  ML Classifier    | ---> |  Alert/Block/Log  |
+-------------------+      +-------------------+      +-------------------+
        |                        |                           |
        v                        v                           v
   [captured_packets.csv]   [rf_model.joblib]         [alerts.log]
        |                        |                           |
        +------------------------+---------------------------+
                                 |
                                 v
                        [Streamlit Dashboard]
```

---

## 📦 Project Structure
```
.
├── data/                # Datasets, logs, and captured packets
├── models/              # Trained ML models and encoders
├── src/                 # Source code (sniffer, ML, detection, threat intel)
├── backend/             # FastAPI API and WebSocket server
├── frontend/            # React/Vite dashboard
├── dashboard/           # Legacy Streamlit dashboard app
├── requirements.txt     # Python dependencies
├── Dockerfile           # Docker build file
├── entrypoint.sh        # Entrypoint script for Docker
└── README.md            # This file
```

---

## ⚡ Quickstart (Local)

### 1. Clone the Repository
```sh
git clone <repo-url>
cd ai-powered-ids-for-home-networks
```

### 2. Set Up Python Environment
```sh
python -m venv venv
venv\Scripts\activate  # On Windows
# or
source venv/bin/activate  # On Linux/Mac
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Prepare Dataset & Train Model

Start the dashboard and click **Download and train with NSL-KDD**, or upload a
labeled CSV from the sidebar. The dashboard saves the prepared dataset and
model files automatically; no dataset preparation script is required.

Alternatively, open the dashboard and use **Train From Your Dataset** in the
sidebar to upload a CSV and train without downloading NSL-KDD. The CSV must
include `protocol_type`, `src_bytes`, `dst_bytes`, and `label` columns. The
dashboard also accepts a headerless 42-column NSL-KDD-shaped CSV. `label`
should include at least two classes; `normal` or `benign` is treated as normal
traffic by real-time detection.

### 4. Start Packet Capture
```sh
python src/sniffer.py           # Run in a separate terminal
```

### 5. (Optional) Set AbuseIPDB API Key
Get a free API key from [AbuseIPDB](https://www.abuseipdb.com/).
```sh
$env:ABUSEIPDB_API_KEY="your_api_key_here"  # Windows
export ABUSEIPDB_API_KEY="your_api_key_here"  # Linux/Mac
```

### 6. Run Real-Time Detection
```sh
python src/realtime_detect.py   # Run in a separate terminal
```

### 7. Launch the Dashboard
```sh
uvicorn backend.main:app --reload --port 8000
```
Visit [http://localhost:8000](http://localhost:8000) in your browser. For local
React development, run `npm install` and `npm run dev` inside `frontend/`.

---

## 🐳 Docker Usage

### 1. Build the Docker Image
```sh
docker build -t ai-ids .
```

### 2. Run the Container
**On Windows (PowerShell):**
```sh
docker run --rm -it -p 8000:8000 -e ABUSEIPDB_API_KEY="your_api_key_here" -v "${PWD}/data:/app/data" ai-ids
```
**On Linux/Mac:**
```sh
docker run --rm -it --net=host -e ABUSEIPDB_API_KEY="your_api_key_here" -v "$(pwd)/data:/app/data" ai-ids
```
- The dashboard will be available at [http://localhost:8000](http://localhost:8000)
- All data and logs are persisted in the `data/` directory on your host.

---

## 🛠️ Troubleshooting
- **Docker port not working on Windows/Mac:** Use `-p 8501:8501` instead of `--net=host`.
- **Volume mount errors:** Use absolute paths or `${PWD}`/`%cd%` as appropriate for your shell.
- **No dashboard:** Check `docker logs <container_id>` for errors.
- **Permission errors:** Run Docker as administrator or with elevated privileges.
- **Firewall/Antivirus:** Ensure port 8501 is open and not blocked.
- **Packet capture permissions:** On Linux, you may need to run as root or with `--cap-add=NET_ADMIN`.

---

## 🔒 Security & Ethics
- **For home/lab use only.**
- **Auto-blocking** can disrupt your network if misused—use with caution.
- **Do not use on networks you do not own or have permission to monitor.**

---

## 🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Open a pull request

---

## 📄 License
MIT License. See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements
- [Scapy](https://scapy.net/)
- [scikit-learn](https://scikit-learn.org/)
- [Streamlit](https://streamlit.io/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [NSL-KDD Dataset](https://www.unb.ca/cic/datasets/nsl.html) 
