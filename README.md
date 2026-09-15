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
