import scapy.all as scapy
from scapy.layers import http
from collections import Counter
import datetime
import json

# Store captured packets info
captured_data = {
    "packets": [],
    "ip_counter": Counter(),
    "protocol_counter": Counter(),
    "total": 0
}

def get_protocol(packet):
    if packet.haslayer(scapy.TCP):
        return "TCP"
    elif packet.haslayer(scapy.UDP):
        return "UDP"
    elif packet.haslayer(scapy.ICMP):
        return "ICMP"
    else:
        return "OTHER"

def analyze_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = get_protocol(packet)
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        size = len(packet)

        # Update counters
        captured_data["ip_counter"][src_ip] += 1
        captured_data["protocol_counter"][protocol] += 1
        captured_data["total"] += 1

        # Store packet info
        packet_info = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "size": size
        }
        captured_data["packets"].append(packet_info)

        # Print live
        print(f"[{timestamp}] {protocol} | {src_ip} → {dst_ip} | Size: {size} bytes")

def save_report():
    filename = f"traffic_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump({
            "total_packets": captured_data["total"],
            "protocol_summary": dict(captured_data["protocol_counter"]),
            "top_source_ips": dict(captured_data["ip_counter"].most_common(10)),
            "packets": captured_data["packets"]
        }, f, indent=4)
    print(f"\n✅ Report saved as '{filename}'")

def print_summary():
    print("\n" + "="*50)
    print("         TRAFFIC ANALYSIS SUMMARY")
    print("="*50)
    print(f"Total Packets Captured : {captured_data['total']}")
    print("\nProtocol Breakdown:")
    for proto, count in captured_data["protocol_counter"].items():
        print(f"  {proto:10} : {count} packets")
    print("\nTop 5 Source IPs:")
    for ip, count in captured_data["ip_counter"].most_common(5):
        print(f"  {ip:20} : {count} packets")
    print("="*50)

def start_capture(interface, packet_count):
    print("="*50)
    print("     Network Traffic Analyzer")
    print("="*50)
    print(f"Interface : {interface}")
    print(f"Capturing : {packet_count} packets")
    print(f"Started   : {datetime.datetime.now()}")
    print("="*50)
    print("Live Capture:")
    print("-"*50)

    try:
        scapy.sniff(iface=interface, prn=analyze_packet, count=packet_count, store=False)
    except PermissionError:
        print("❌ Permission denied! Run with sudo:")
        print("   sudo python3 traffic_analyzer.py")
        return
    except Exception as e:
        print(f"❌ Error: {e}")
        return

    print_summary()
    save_report()

if __name__ == "__main__":
    print("\n🔍 Network Traffic Analyzer")
    print("-"*30)
    interface = input("Enter network interface (e.g. eth0, wlan0, lo): ")
    count = int(input("Enter number of packets to capture (e.g. 50): "))
    start_capture(interface, count)