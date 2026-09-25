# Network Traffic Analysis - Teardrop PCAP

## 1. Objective

The objective of this analysis is to investigate the traffic present in the `teardrop.cap` file, identify anomalous behavior, and document the observed evidence using TShark.

The analysis was performed on a PCAP containing 17 frames, with a focus on IPv4 communication, packet fragmentation, UDP traffic, and DNS context.

## 2. Methodology

The file was analyzed using TShark on Kali Linux.

TShark filters and features were used to:

* count the frames present in the capture;
* identify the protocol hierarchy;
* locate IPv4 fragments;
* compare the fields of the fragments;
* analyze frames 8 and 9 in detail;
* examine the data in hexadecimal format;
* verify fragment reassembly;
* investigate DNS traffic related to the `129.111.30.27` address.

The evidence generated during the analysis was stored in the `evidence/` directory.

## 3. Traffic Overview

The capture contains 17 frames.

The frames include LOOP, CDP, DNS, IPv4/UDP, ARP, and ICMP traffic.

The IPv4 communication observed by TShark can be grouped into three main conversations:

* `10.0.0.6 ↔ 151.164.1.8` -  2 frames, related to DNS;
* `10.1.1.1 ↔ 129.111.30.27` -  2 frames, related to IPv4/UDP fragmentation;
* `10.0.0.6 ↔ 10.0.0.254` — 2 frames, related to ICMP.

The communication between `10.1.1.1` and `129.111.30.27` has a duration of approximately `0.0004` seconds, corresponding to frames 8 and 9.

These two frames are the main focus of the investigation due to the anomalies observed in IPv4 fragmentation and the UDP protocol.

## 4. DNS Analysis

The DNS activity in the capture consists of two frames.

Frame 6 contains a DNS query from `10.0.0.6` to `151.164.1.8` requesting the IPv4 address of `picard.uthscsa.edu`.

Frame 7 contains the corresponding DNS response from `151.164.1.8` to `10.0.0.6`. The response associates `picard.uthscsa.edu` with the IPv4 address `129.111.30.27`.

The relevant sequence is:

```text
10.0.0.6 → 151.164.1.8
DNS query: picard.uthscsa.edu

151.164.1.8 → 10.0.0.6
DNS response:
picard.uthscsa.edu → 129.111.30.27
```

Frame 7 occurs at approximately `30.612811` seconds into the capture. Approximately `2.182` milliseconds later, frame 8 records traffic from `10.1.1.1` to `129.111.30.27`.

This establishes a temporal relationship between the DNS response and subsequent traffic to the resolved address. However, the capture does not establish that `10.0.0.6` generated the subsequent traffic, since the source address of frames 8 and 9 is `10.1.1.1`.

## 5. Fragment Analysis

Frames 8 and 9 contain IPv4 traffic from `10.1.1.1` to `129.111.30.27`.

Both frames use the same IPv4 Identification value:

```text
0x00f2
```

This indicates that the frames belong to the same IPv4 fragmentation sequence.

### Frame 8

Frame 8 contains the following IPv4 fragmentation fields:

* Source: `10.1.1.1`
* Destination: `129.111.30.27`
* Identification: `0x00f2`
* Total Length: `56` bytes
* Fragment Offset: `0`
* More Fragments flag: set
* Protocol: UDP

The fragment begins at offset `0` and indicates that additional fragments follow.

### Frame 9

Frame 9 contains the following fields:

* Source: `10.1.1.1`
* Destination: `129.111.30.27`
* Identification: `0x00f2`
* Total Length: `24` bytes
* Fragment Offset: `24` bytes
* More Fragments flag: not set
* Protocol: UDP

The TShark field `ip.frag_offset` is reported as `3`. IPv4 fragment offsets are measured in units of 8 bytes, so the actual offset is:

```text
3 × 8 = 24 bytes
```

Because the two frames have the same Identification value, source address, and destination address, they are associated with the same fragmented IPv4 datagram.

The fragment in frame 8 contains 36 bytes of IP data and starts at byte `0`. Its data therefore covers bytes `0–35`.

The fragment in frame 9 starts at byte `24` and contains 4 bytes of IP data. Its data covers bytes `24–27`.

The ranges overlap:

```text
Frame 8: bytes 0–35
Frame 9: bytes 24–27
```

This overlap is an anomaly in the IPv4 fragmentation structure. TShark reports the following conditions during reassembly:

* `Fragment too long: True`
* `Fragment overlap: True`
* `Conflicting data in fragment overlap: True`

The hexadecimal output shows that the visible overlapping bytes are `7c ab 4e e5`. The report therefore distinguishes between the bytes visible in the hex dump and TShark's interpretation of the fragment reassembly.

## 6. UDP Anomaly

Frame 9 contains a UDP segment carried inside the fragmented IPv4 datagram.

The UDP communication uses source port `31915` and destination port `20197`.

TShark reports the following UDP information:

```text
Source port: 31915
Destination port: 20197
UDP Length: 36 bytes
IP payload available: 28 bytes
```

The UDP length field indicates a 36-byte UDP segment, but only 28 bytes are available in the reconstructed IPv4 data. TShark therefore identifies the packet as malformed and reports:

```text
[BAD UDP LENGTH 36 > IP PAYLOAD LENGTH]
```

The packet is also reported with the expert information:

```text
Bad length value 36 > IP payload length
```

This inconsistency provides an additional indication that the datagram is malformed.

The UDP anomaly is independent evidence from the IPv4 fragmentation anomaly. The IPv4 analysis identified overlapping fragments, while the UDP analysis shows that the length declared by the UDP header exceeds the available IP payload.

Together, these observations show that frames 8 and 9 contain multiple structural inconsistencies that affect normal packet reassembly and protocol interpretation.

## 7. Fragment Reassembly

TShark's reassembly information was extracted from frame 9 using the `ip.reassembled` fields.

The result shows:

```text
Frame: 9
IP Identification: 0x00f2
Fragment Offset: 3
More Fragments: False
Reassembled Length: 28 bytes
```

Because the fragment offset is `3`, the fragment begins at byte `24` of the original IPv4 payload.

TShark associates frame 9 with two IPv4 fragments:

```text
Frame 8: 36 bytes
Frame 9: 4 bytes
```

During reassembly, TShark reports:

```text
Fragment too long: True
Fragment overlap: True
Conflicting data in fragment overlap: True
```

The reconstructed data reported by TShark is:

```text
7cab4ee5002400000000000000000000000000000000000000000000
```

The reassembly information supports the previous observation that the fragments do not form a normal, non-overlapping sequence. The same IPv4 Identification value (`0x00f2`) is used by both frames, while the fragment ranges overlap.

The hex dump should be interpreted together with TShark's reassembly metadata. The visible overlapping bytes in the captured fragments are `7c ab 4e e5`, while TShark separately reports conflicting data during its fragment reassembly process.

## 8. Traffic After the Fragmentation Event

After frames 8 and 9, the capture records ARP traffic involving `10.0.0.6` and `10.0.0.254`.

Frames 10 through 13 contain repeated ARP requests:

```text
Who has 10.0.0.254? Tell 10.0.0.6
```

The requests occur approximately one second apart.

Frame 14 contains the corresponding ARP response:

```text
10.0.0.254 is at 00:00:39:cf:d9:cd
```

This indicates that `10.0.0.6` successfully learned the MAC address associated with `10.0.0.254`.

Later in the capture, frames 16 and 17 contain an ICMP echo request and reply:

```text
10.0.0.6 → 10.0.0.254
ICMP Echo request

10.0.0.254 → 10.0.0.6
ICMP Echo reply
```

The ICMP exchange shows that the two hosts successfully exchanged ICMP packets at that point in the capture.

The capture therefore shows continued network activity after the anomalous IPv4 fragmentation. However, these later packets do not by themselves establish whether the fragmentation event affected the hosts or whether any attack succeeded or failed.

## 9. Conclusion

The analysis of `teardrop.cap` identified anomalous IPv4 fragmentation in frames 8 and 9.

Both frames share the same source and destination addresses (`10.1.1.1` → `129.111.30.27`) and the same IPv4 Identification value (`0x00f2`). Their fragment ranges overlap because frame 8 covers bytes `0–35`, while frame 9 begins at byte `24` and contains bytes `24–27`.

TShark reports multiple reassembly anomalies, including `Fragment too long`, `Fragment overlap`, and `Conflicting data in fragment overlap`.

Frame 9 also contains a UDP length inconsistency. The UDP header specifies a length of 36 bytes, while only 28 bytes are available in the IP payload. TShark consequently identifies the packet as malformed.

The capture also contains DNS activity in which `picard.uthscsa.edu` resolves to `129.111.30.27`. Shortly afterward, traffic from `10.1.1.1` to that address appears in frames 8 and 9. However, the different source addresses mean that the capture does not establish that `10.0.0.6` generated the subsequent fragmented traffic.

After the anomalous fragments, the capture continues with ARP traffic and a successful ICMP echo request/reply between `10.0.0.6` and `10.0.0.254`. These later packets demonstrate continued network activity, but they do not establish the impact or outcome of the fragmentation event.

Overall, the PCAP provides direct evidence of malformed IPv4 fragmentation and an inconsistent UDP length field. The findings are based on packet fields, TShark's reassembly analysis, and the captured hexadecimal data rather than assumptions about the intent or outcome of the traffic.

## 10. Evidence and Commands

The following TShark commands were used during the analysis.

### Packet count

```bash
tshark -r pcaps/teardrop.cap | wc -l
```

Output:

```text
17
```

### Protocol hierarchy

```bash
tshark -r pcaps/teardrop.cap -q -z io,phs
```

### IPv4 fragments

```bash
tshark -r pcaps/teardrop.cap \
-Y "ip.flags.mf == 1 || ip.frag_offset > 0"
```

### Fragment summary

```bash
tshark -r pcaps/teardrop.cap \
-Y "ip.id == 0x00f2" \
-T fields \
-e frame.number \
-e ip.src \
-e ip.dst \
-e ip.id \
-e ip.flags \
-e ip.frag_offset \
-e ip.len
```

### Detailed analysis of frames 8 and 9

```bash
tshark -r pcaps/teardrop.cap \
-Y "frame.number == 8 || frame.number == 9" \
-V
```

### Hexadecimal analysis

```bash
tshark -r pcaps/teardrop.cap \
-Y "frame.number == 8 || frame.number == 9" \
-x
```

### IPv4 conversations

```bash
tshark -r pcaps/teardrop.cap \
-q -z conv,ip
```

### DNS summary

```bash
tshark -r pcaps/teardrop.cap \
-Y "dns" \
-T fields \
-e frame.number \
-e ip.src \
-e ip.dst \
-e dns.qry.name \
-e dns.a
```

### Fragment reassembly

```bash
tshark -r pcaps/teardrop.cap \
-Y "frame.number == 9" \
-T fields \
-e frame.number \
-e ip.id \
-e ip.frag_offset \
-e ip.flags.mf \
-e ip.reassembled.length \
-e ip.reassembled.data
```

The command outputs were saved as evidence files in the `evidence/` directory throughout the investigation.
