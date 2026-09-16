import scapy.all as scapy
import pandas as pd
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from alert_store import append_alert

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')
ALERT_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.jsonl')
HOST_MAC = os.environ.get('IDS_HOST_MAC', '00:0c:29:7d:51:17')
SNIFF_INTERFACE = os.environ.get('IDS_SNIFF_INTERFACE')
arp_bindings = {}

features = [
    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_length'
]

def extract_features(packet):
    if not packet.haslayer(scapy.IP):
        return None
    ip_layer = packet[scapy.IP]
    proto = ip_layer.proto
    protocol = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, str(proto))
    src_port = dst_port = None
    if protocol == 'TCP' and packet.haslayer(scapy.TCP):
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport
    elif protocol == 'UDP' and packet.haslayer(scapy.UDP):
        src_port = packet[scapy.UDP].sport
        dst_port = packet[scapy.UDP].dport
    return {
        'timestamp': datetime.now().isoformat(),
        'src_ip': ip_layer.src,
        'dst_ip': ip_layer.dst,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'packet_length': len(packet)
    }

def packet_callback(packet):
    if packet.haslayer(scapy.ARP):
        arp = packet[scapy.ARP]
        if arp.psrc and arp.hwsrc:
            previous_mac = arp_bindings.get(arp.psrc)
            if previous_mac and previous_mac.lower() != arp.hwsrc.lower():
                message = (
                    f'ALERT: ARP spoofing suspected: {arp.psrc} changed from '
                    f'{previous_mac} to {arp.hwsrc}'
                )
                alert = append_alert(
                    ALERT_PATH, message, 90, 'arp_spoofing',
                    {'src_ip': arp.psrc, 'src_mac': arp.hwsrc, 'previous_mac': previous_mac},
                )
                print(alert['message'], flush=True)
            arp_bindings[arp.psrc] = arp.hwsrc
        return
    feat = extract_features(packet)
    if feat:
        df = pd.DataFrame([feat])
        if not os.path.exists(DATA_PATH):
            df.to_csv(DATA_PATH, index=False, mode='w', header=True)
        else:
            df.to_csv(DATA_PATH, index=False, mode='a', header=False)
        print(feat, flush=True)

if __name__ == '__main__':
    print('Starting packet capture... Press Ctrl+C to stop.', flush=True)
    sniff_options = {
        'filter': f'not ether host {HOST_MAC}',
        'prn': packet_callback,
        'store': 0,
    }
    if SNIFF_INTERFACE:
        sniff_options['iface'] = SNIFF_INTERFACE
    scapy.sniff(**sniff_options)