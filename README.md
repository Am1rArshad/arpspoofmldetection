# AI-Powered Intrusion Detection System (IDS) for Home Networks

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
