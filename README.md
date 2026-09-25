# Network Traffic Analysis

A hands-on network traffic analysis project using TShark to investigate packet captures, identify anomalous traffic, and document network evidence.

## Project Overview

This project focuses on the analysis of PCAP files using command-line network analysis tools.

The first investigation analyzes `teardrop.cap`, a packet capture containing IPv4 fragmentation and UDP traffic with multiple protocol inconsistencies.

The analysis was performed in Kali Linux using TShark.

## Objectives

* Analyze network traffic from PCAP files
* Identify relevant hosts and conversations
* Investigate IPv4 fragmentation
* Analyze UDP protocol fields
* Examine DNS activity and its relationship to subsequent traffic
* Investigate packet reassembly
* Preserve command output as evidence
* Document findings in a reproducible format

## Tools

* Kali Linux
* TShark
* Wireshark-compatible PCAP files
* Linux command line

## Directory Structure

```text
network-traffic-analysis/
├── evidence/
├── notes/
├── pcaps/
├── report/
├── screenshots/
└── README.md
```

### Evidence

The `evidence/` directory contains the outputs generated during the investigation, including:

* packet counts
* protocol hierarchy
* IPv4 fragment information
* fragment summaries
* detailed packet information
* hexadecimal packet data
* DNS information
* fragment reassembly information

### PCAPs

The `pcaps/` directory contains the packet captures analyzed in the project.

Current investigation:

```text
pcaps/
└── teardrop.cap
```

## Teardrop PCAP — Key Findings

The capture contains 17 frames.

Frames 8 and 9 are the main focus of the investigation. Both belong to traffic from:

```text
10.1.1.1 → 129.111.30.27
```

The two frames share the IPv4 Identification value:

```text
0x00f2
```

The fragments have overlapping ranges:

```text
Frame 8: bytes 0–35
Frame 9: bytes 24–27
```

TShark reports:

```text
Fragment too long: True
Fragment overlap: True
Conflicting data in fragment overlap: True
```

Frame 9 also contains a UDP length inconsistency. The UDP header specifies a length of 36 bytes, while the available IP payload is 28 bytes.

TShark therefore reports:

```text
BAD UDP LENGTH 36 > IP PAYLOAD LENGTH
```

The capture also contains DNS activity involving `picard.uthscsa.edu`. The DNS response associates the domain with `129.111.30.27`, followed approximately 2.2 milliseconds later by traffic from `10.1.1.1` to that address.

The capture does not establish that `10.0.0.6` generated the subsequent fragmented traffic because the source addresses are different.

## Documentation

Detailed technical analysis is available in:

```text
report/teardrop-analysis.md
```

The report documents the methodology, DNS activity, IPv4 fragmentation, UDP anomaly, fragment reassembly, subsequent traffic, and the commands used during the investigation.

## Disclaimer

This project is intended for cybersecurity learning and network traffic analysis practice. The analysis is based on the contents of the captured PCAP files and does not assume information that cannot be established from the available packet data.
