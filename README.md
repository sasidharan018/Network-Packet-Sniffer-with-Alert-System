# Network-Packet-Sniffer-with-Alert-System
Command-line packet sniffer with anomaly detection using Python which captures live traffic, stores relevant metadata into an SQLite database, and monitors for network anomalies such as flooding and port scanning.

## Introduction
This project is a **CLI-based network traffic sniffer with anomaly detection**, built using **Python, Scapy, and SQLite**.  
It captures live packets, logs them into a database, and detects suspicious activities such as **flooding attacks** and **port scans**.  
The tool provides a real-time alerting mechanism via log files and allows further analysis with SQL queries.

---

## Features
- Live packet capture using **Scapy**
- Stores packet metadata in **SQLite database**
- Detects:
  - **Flooding** (packet/byte rate threshold)
  - **Port Scanning** (distinct ports contacted within a time window)
- Logs anomalies in both:
  - **SQLite database (alerts table)**
  - **alerts.log** file
- Configurable thresholds via CLI arguments
- Simple, lightweight **CLI tool** (no GUI required)

---

## Tools Used
- **Python 3.x**
- **Scapy** (for packet sniffing)
- **SQLite** (for logging and analysis)

---

## Installation

1. Install Python (3.8+ recommended).
2. Install dependencies:
   ```bash
   pip install scapy
3. SQLite is built into Python, no need to install separately.
4. On Windows, install Npcap with WinPcap compatibility mode enabled.
On Linux, run the script with sudo.

---

## Usage

Run the tool with administrator/root privileges.

**Example:**

python cli_sniffer_simple.py --iface "Ethernet" --window 10 --pkt-th 2000 --byte-th 5000000 --portscan 100

**Options:**

**Argument	 Description**
--iface	     Network interface to sniff (e.g., "Ethernet", "Wi-Fi")
--window	   Sliding window in seconds (default: 10)
--pkt-th	   Packet flood threshold per source per window (default: 2000)
--byte-th	   Byte flood threshold per source per window (default: 5000000 ≈ 5 MB)
--portscan   Distinct port threshold for port scanning (default: 100)
--db	       Path to SQLite DB file (default: traffic.db)
--alerts	   Path to alerts log file (default: alerts.log)

---

## Project Workflow Diagram

┌───────────────────┐
        │   Network Traffic │
        └─────────┬─────────┘
                  │ (captured by Scapy)
        ┌─────────▼─────────┐
        │   Packet Parser    │
        └─────────┬─────────┘
                  │ (extract IP, ports, length, flags)
        ┌─────────▼─────────┐
        │   SQLite Database  │
        │  - packets table   │
        │  - alerts table    │
        └─────────┬─────────┘
                  │ (anomaly detection checks)
        ┌─────────▼─────────┐
        │ Anomaly Detection │
        │ - Flooding        │
        │ - Port Scanning   │
        └─────────┬─────────┘
                  │ (alerts generated)
        ┌─────────▼─────────┐
        │   Alerts Output    │
        │ - alerts.log file  │
        │ - DB alerts table  │
        └────────────────────┘


---

## Database Schema

The tool uses SQLite (traffic.db) with two tables:

1. packets Table
   
**Column	  Description**

id	        Auto-increment primary key
ts	        Timestamp (epoch)
src_ip	    Source IP address
dst_ip	    Destination IP address
src_port	  Source port
dst_port	  Destination port
length	    Packet length
flags	      TCP flags

2. alerts Table
   
**Column	Description**

id	      Auto-increment primary key
ts	      Timestamp (epoch)
type	    Type of anomaly (FLOOD, PORTSCAN)
src	      Source IP address
details	  Additional info about the alert


---

## Example SQL Queries

1. Top talkers (most packets by source IP):

SELECT src_ip, COUNT(*) AS pkt_count 
FROM packets 
GROUP BY src_ip 
ORDER BY pkt_count DESC 
LIMIT 10;


2. Alerts history:

SELECT type, src, details, datetime(ts,'unixepoch') 
FROM alerts 
ORDER BY ts DESC;


3. Traffic volume by source:

SELECT src_ip, SUM(length) AS total_bytes 
FROM packets 
GROUP BY src_ip 
ORDER BY total_bytes DESC 
LIMIT 10;

---

## Logs

alerts.log file contains all detected anomalies in plain text.

To monitor in real-time,
Linux: tail -f alerts.log
Windows (PowerShell): Get-Content .\alerts.log -Wait


---

## Conclusion

This project demonstrates a practical intrusion detection concept using Python.
By capturing traffic, storing structured logs, and applying anomaly detection, it serves as a lightweight and extensible foundation for further IDS/IPS development.
