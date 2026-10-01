# SIH PS 26145 --- Cyber Threat Detection Dataset Collection

> **Project:** AI-Based Detection of Cyber Threats in Unidirectional IP
> Traffic\
> **Purpose:** Dataset/reference list for training, validation, feature
> extraction, and controlled traffic generation.

------------------------------------------------------------------------

## 1. Recommended Core Network IDS Datasets

### 1.1 CIC-IDS2017 ⭐⭐⭐

-   Official page: https://www.unb.ca/cic/datasets/ids-2017.html
-   Contains: benign traffic, brute force, DoS, DDoS, Heartbleed, web
    attacks, infiltration, botnet, port scan.
-   Formats: PCAP + labeled flow CSV.
-   Features: 80+ CICFlowMeter features.
-   Recommended use: general intrusion detection baseline.

### 1.2 CSE-CIC-IDS2018 ⭐⭐⭐

-   Official page: https://www.unb.ca/cic/datasets/ids-2018.html
-   AWS Open Data: https://registry.opendata.aws/cse-cic-ids2018/
-   AWS bucket: `s3://cse-cic-ids2018/`
-   Contains: brute force, Heartbleed, botnet, DoS, DDoS, web attacks,
    infiltration.
-   Formats: PCAP, logs, processed CSV.
-   Recommended use: modern/general NIDS training and cross-dataset
    validation.

### 1.3 CIC-DDoS2019 ⭐⭐⭐

-   Official page: https://www.unb.ca/cic/datasets/ddos-2019.html
-   Contains: PortMap, NetBIOS, LDAP, MSSQL, UDP, UDP-Lag, SYN, NTP,
    DNS, SNMP, SSDP, WebDDoS, TFTP and other DDoS traffic.
-   Formats: PCAP + labeled flow CSV.
-   Recommended use: DDoS/SYN/UDP detection.

### 1.4 UNSW-NB15 ⭐⭐⭐

-   Official page:
    https://research.unsw.edu.au/projects/unsw-nb15-dataset
-   Contains: normal, fuzzers, analysis, backdoors, DoS, exploits,
    generic, reconnaissance, shellcode, worms.
-   Recommended use: general attack classification and external
    validation.

### 1.5 NF-UQ-NIDS / NF-UQ-NIDS-v2 ⭐⭐⭐

-   Dataset page: https://staff.itee.uq.edu.au/marius/NIDS_datasets/
-   Flow-based network intrusion datasets using a standardized feature
    representation.
-   Recommended use: large-scale flow training and cross-dataset
    evaluation.

------------------------------------------------------------------------

## 2. Botnet, C2 and Malware Traffic

### 2.1 CTU-13 ⭐⭐⭐

-   Official page: https://www.stratosphereips.org/datasets-overview/
-   Contains: 13 botnet scenarios with botnet, normal and background
    traffic.
-   Recommended use: C2/botnet behavioral detection.

### 2.2 IoT-23 ⭐⭐⭐

-   Official page: https://www.stratosphereips.org/datasets-iot23
-   Full dataset:
    https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/iot_23_datasets_full.tar.gz
-   Smaller dataset:
    https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/iot_23_datasets_small.tar.gz
-   Contains: malicious and benign IoT scenarios, PCAP and Zeek flow
    logs.
-   Recommended use: IoT botnet/malware/C2 detection.

### 2.3 USTC-TFC2016

-   Repository: https://github.com/yungshenglu/USTC-TFC2016
-   Contains benign application traffic and malware traffic such as
    Cridex, Geodo, Htbot, Miuref, Neris, Shifu, Tinba, Virut and Zeus.
-   Recommended use: malware traffic classification.

### 2.4 Bot-IoT ⭐⭐⭐

-   Official page: https://research.unsw.edu.au/projects/bot-iot-dataset
-   Contains: DDoS, DoS, scanning, keylogging and data exfiltration.
-   Formats: PCAP, Argus and CSV.
-   Recommended use: IoT attack detection and large-scale flow
    experiments.

### 2.5 TON_IoT ⭐⭐⭐

-   Official page: https://research.unsw.edu.au/projects/toniot-datasets
-   Contains: IoT/IIoT telemetry, network traffic, Windows/Linux data,
    TLS and security events.
-   Recommended use: heterogeneous IoT/IIoT cybersecurity experiments.

------------------------------------------------------------------------

## 3. Real-World / Background Traffic

### 3.1 MAWI Traffic Archive ⭐⭐⭐

-   Official archive: https://mawi.wide.ad.jp/mawi/
-   Contains real network traces from the WIDE backbone.
-   Recommended use: realistic benign/background traffic and
    generalization testing.

### 3.2 UGR'16 ⭐⭐⭐

-   Official page: https://nesg.ugr.es/nesg-ugr16/
-   Based on NetFlow v9 traffic from an ISP environment.
-   Contains background traffic and synthetic attacks.
-   Recommended use: testing whether the model generalizes beyond
    laboratory datasets.

------------------------------------------------------------------------

## 4. VPN / Tor / Encrypted Traffic

### 4.1 ISCX VPN-nonVPN 2016

-   Official page: https://www.unb.ca/cic/datasets/vpn.html
-   Contains VPN and non-VPN traffic for browsing, email, chat, VoIP,
    streaming, FTP and P2P.
-   Recommended use: encrypted/VPN traffic behavior.

### 4.2 ISCX Tor-nonTor 2016

-   Official page: https://www.unb.ca/cic/datasets/tor.html
-   Contains Tor and non-Tor traffic across several application
    categories.
-   Recommended use: anonymity-network traffic classification.

------------------------------------------------------------------------

## 5. DGA / DNS Threat Intelligence

### 5.1 DGA Domains Dataset ⭐⭐⭐

-   Repository: https://github.com/chrmor/DGA_domains_dataset
-   Contains approximately 675K domains, including benign and DGA
    domains across multiple DGA families.
-   Recommended use: DGA classification.

### 5.2 DGA Collection

-   Repository: https://github.com/pchaigno/dga-collection
-   Contains implementations/data for multiple DGA families.
-   Recommended use: generating additional DGA samples and
    family-specific testing.

### 5.3 DGA Dataset / Algorithms

-   Repository: https://github.com/andrewaeva/dga
-   Includes DGA algorithms and legitimate-domain data.
-   Recommended use: synthetic DGA generation and experimentation.

### 5.4 ExtraHop DGA Detection Training Dataset ⭐⭐⭐

-   Repository:
    https://github.com/ExtraHop/DGA-Detection-Training-Dataset
-   Large DGA-focused training dataset.
-   Recommended use: dedicated DNS/DGA classifier.

------------------------------------------------------------------------

## 6. Controlled Lab Traffic Generation

> Generate these only inside an isolated, authorized lab environment.

### 6.1 iperf3 --- Benign Traffic

-   Repository: https://github.com/esnet/iperf
-   Use for: TCP/UDP throughput, long-lived flows, variable bandwidth
    and benign background traffic.

### 6.2 Ostinato --- Packet/Traffic Generator

-   Repository: https://github.com/pstavirs/ostinato
-   Use for: controlled TCP/UDP/ICMP traffic and custom packet patterns.

### 6.3 TRex --- High-Speed Traffic Generator

-   Repository:
    https://github.com/cisco-system-traffic-generator/trex-core
-   Use for: high-rate and large-scale traffic generation.

------------------------------------------------------------------------

## 7. Controlled Attack Traffic Generation

> Use only against systems you own or are explicitly authorized to test.

### 7.1 hping3

-   Repository: https://github.com/antirez/hping
-   Lab use: TCP/UDP/ICMP packet-pattern experiments and controlled
    flood traffic.

### 7.2 Slowloris

-   Repository: https://github.com/gkbrk/slowloris
-   Lab use: slow HTTP connection-exhaustion traffic.

### 7.3 dnscat2

-   Repository: https://github.com/iagox86/dnscat2
-   Lab use: DNS tunneling traffic and covert-channel behavior.

### 7.4 iodine

-   Repository: https://github.com/yarrick/iodine
-   Lab use: DNS tunneling traffic.

------------------------------------------------------------------------

## 8. DDoS / Historical Dataset

### 8.1 CAIDA DDoS Attack 2007

-   Official page:
    https://www.caida.org/catalog/datasets/ddos-20070804_dataset/
-   Contains anonymized DDoS traffic traces.
-   Access may require CAIDA's dataset request/acceptable-use process.
-   Recommended use: historical external validation, not as the only
    training source.

------------------------------------------------------------------------

## 9. Feature Extraction Tools

### 9.1 Zeek

-   Official site: https://zeek.org/
-   Repository: https://github.com/zeek/zeek
-   Useful logs:
    -   `conn.log`
    -   `dns.log`
    -   `http.log`
    -   `ssl.log`
    -   `ssh.log`
-   Recommended use: extracting protocol-aware network behavior from
    PCAP.

### 9.2 CICFlowMeter

-   Repository: https://github.com/ahlashkari/CICFlowMeter
-   Recommended use: generating flow-level statistical features
    comparable to CIC datasets.

### 9.3 Argus

-   Official site: https://openargus.org/
-   Recommended use: network-flow auditing and feature extraction.

### 9.4 Wireshark / tshark

-   Official site: https://www.wireshark.org/
-   Recommended use: PCAP inspection, protocol analysis and validation.

------------------------------------------------------------------------

# 10. Dataset-to-Feature Mapping

  -----------------------------------------------------------------------
  Dataset                 Main purpose            Useful features
  ----------------------- ----------------------- -----------------------
  CIC-IDS2017             General IDS             Flow statistics, TCP
                                                  flags, rates

  CSE-CIC-IDS2018         General IDS             Flow + protocol +
                                                  timing

  CIC-DDoS2019            DDoS                    Packet rate, byte rate,
                                                  flags, burstiness

  UNSW-NB15               General IDS             Flow + statistical
                                                  features

  NF-UQ-NIDS-v2           Large-scale flow IDS    Standardized flow
                                                  features

  CTU-13                  C2/Botnet               Timing, destination
                                                  behavior, connection
                                                  patterns

  IoT-23                  IoT malware/C2          Zeek connection and DNS
                                                  features

  Bot-IoT                 IoT attacks             Flow, protocol and
                                                  attack statistics

  TON_IoT                 IoT/IIoT                Network + telemetry +
                                                  security events

  USTC-TFC2016            Malware                 Flow/application
                                                  behavior

  MAWI                    Real benign             Real-world traffic
                                                  distributions

  UGR'16                  ISP traffic             NetFlow behavior

  DGA datasets            DGA                     Entropy, length,
                                                  n-grams, digit ratio

  dnscat2/iodine          DNS tunneling           Query length,
                                                  frequency, entropy

  Slowloris               Slow HTTP               Duration, IAT,
                                                  connection rate

  hping3                  Packet attacks          Flags, packet rate,
                                                  protocol statistics

  iperf3                  Benign                  Throughput, packet
                                                  rate, duration
  -----------------------------------------------------------------------

------------------------------------------------------------------------

# 11. Recommended Dataset Architecture

``` text
                    DATA SOURCES
                         |
       +-----------------+------------------+
       |                 |                  |
   Public IDS        Real Traffic       Lab Traffic
       |                 |                  |
 CIC-IDS2017           MAWI             iperf3
 CSE-CIC-IDS2018       UGR'16            Ostinato
 CIC-DDoS2019                            TRex
 UNSW-NB15
 NF-UQ-NIDS
       |
       +-----------------+
                         |
               Botnet / Malware
                         |
             CTU-13 / IoT-23
             Bot-IoT / USTC
                         |
                         |
                    DNS Threats
                         |
             DGA / dnscat2 / iodine
                         |
                         v
                 PCAP / Flow / DNS
                         |
                         v
                Feature Extraction
                  Zeek / CICFlowMeter
                         |
                         v
                  Unified Dataset
                         |
                         v
                  ML / DL Models
                         |
                         v
             Threat Classification
```

------------------------------------------------------------------------

# 12. Recommended Final Training Split

## General Threat Model

Use:

``` text
CIC-IDS2017
CSE-CIC-IDS2018
UNSW-NB15
NF-UQ-NIDS-v2
```

Classes:

``` text
BENIGN
DOS
DDOS
SCAN
BRUTE_FORCE
BOT
EXPLOIT
INFILTRATION
OTHER_ATTACK
```

## C2 / Malware Model

Use:

``` text
CTU-13
IoT-23
USTC-TFC2016
Bot-IoT
TON_IoT
```

Classes:

``` text
BENIGN
BOTNET
C2
MALWARE
DATA_EXFILTRATION
```

## DNS Intelligence Model

Use:

``` text
DGA Domains Dataset
ExtraHop DGA Dataset
DGA Collection
dnscat2
iodine
```

Classes:

``` text
BENIGN_DNS
DGA
DNS_TUNNEL
```

------------------------------------------------------------------------

# 13. Important Dataset Rules

1.  Do not train on IP addresses directly.
2.  Avoid random row-level train/test splits when flows from the same
    capture appear in both sets.
3.  Prefer capture/day/scenario-based splits.
4.  Keep at least one completely unseen dataset for external validation.
5.  Normalize feature names across datasets before merging.
6.  Keep original dataset labels in a `source_label` column.
7.  Create your own unified label taxonomy.
8.  Do not blindly merge CICFlowMeter and Zeek features; define a common
    schema.
9.  Deduplicate flows before training.
10. Check class imbalance before training.
11. Measure performance separately for each dataset.
12. Report cross-dataset generalization, not only random-split accuracy.

------------------------------------------------------------------------

# 14. Suggested Unified Schema

``` text
timestamp
src_ip
dst_ip
src_port
dst_port
protocol

duration
packet_count
byte_count
packet_rate
byte_rate

mean_packet_size
std_packet_size
min_packet_size
max_packet_size

mean_iat
std_iat
min_iat
max_iat

syn_count
ack_count
rst_count
fin_count
psh_count
urg_count

dns_query_length
dns_entropy
dns_label_count
dns_digit_ratio
nxdomain_ratio

src_port_entropy
dst_port_entropy
burst_rate
idle_time

source_dataset
scenario
attack_family
label
```

------------------------------------------------------------------------

# 15. Priority Order for SIH MVP

If storage/compute is limited, start with:

``` text
1. CIC-IDS2017
2. UNSW-NB15
3. CIC-DDoS2019
4. CTU-13
5. IoT-23
6. DGA Domains Dataset
7. MAWI
8. Your own iperf3/Ostinato traffic
9. Your own DNS tunneling traffic
10. Your own Slowloris traffic
```

Then add:

``` text
CSE-CIC-IDS2018
NF-UQ-NIDS-v2
Bot-IoT
TON_IoT
UGR'16
USTC-TFC2016
ExtraHop DGA
```

------------------------------------------------------------------------

## Official Dataset Indexes

-   Canadian Institute for Cybersecurity datasets:
    https://www.unb.ca/cic/datasets/
-   UNSW cybersecurity datasets: https://research.unsw.edu.au/
-   Stratosphere datasets:
    https://www.stratosphereips.org/datasets-overview/
-   MAWI archive: https://mawi.wide.ad.jp/mawi/
-   UQ NIDS datasets: https://staff.itee.uq.edu.au/marius/NIDS_datasets/

------------------------------------------------------------------------

## Suggested Project Name

**FlowSentinel --- AI-Powered Cyber Threat Detection from Unidirectional
IP Traffic**

### One-line project description

> FlowSentinel combines heterogeneous public network-security datasets,
> real-world traffic, controlled laboratory traffic, DNS intelligence
> and flow-level behavioral features to detect and classify cyber
> threats from unidirectional IP traffic.
