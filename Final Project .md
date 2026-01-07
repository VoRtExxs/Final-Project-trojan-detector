# **🛡️ AI-Driven Trojan Detection Using Network Traffic Analysis**

**PCAP → Zeek → CSV Logs → Behavioral Features → Random Forest**

## **Overview**

This repository implements an end-to-end pipeline to detect Trojan-related malware from network behavior (PCAP files), using Zeek logs and machine learning. Each PCAP is processed into a fixed-length feature vector (60+ behavioral features), then classified into:

* RAT (Remote Access Trojan)  
* Downloader  
* Botnet  
* Benign

## **Architecture**

Plaintext

┌─────────────┐  
│ PCAP Files  │  
└──────┬──────┘  
       │  
       ▼  
┌─────────────────────┐  
│ Zeek Analysis       │  
│ (build\_zeek\_csvs.sh)│  
└──────┬──────────────┘  
       │  
       ▼  
┌─────────────────────────┐  
│ CSV Logs                │  
│ (conn, dns, http, ssl)  │  
└──────┬──────────────────┘  
       │  
       ▼  
┌──────────────────────────┐  
│ Feature Extraction       │  
│ (features\_from\_zeek.py)  │  
└──────┬───────────────────┘  
       │  
       ▼  
┌──────────────────────────┐  
│ features\_dataset.csv     │  
│ (60+ behavioral features)│  
└──────┬───────────────────┘  
       │  
       ▼  
┌──────────────────────────┐  
│ Model Training           │  
│ (train\_model.py)         │  
└──────┬───────────────────┘  
       │  
       ▼  
┌──────────────────────────┐  
│ Trained Model            │  
│ (trojan\_rf.joblib)       │  
└──────┬───────────────────┘  
       │  
       ▼  
┌──────────────────────────┐  
│ PCAP Scanning            │  
│ (pcap\_scan.py)           │  
└──────┬───────────────────┘  
       │  
       ▼  
┌──────────────────────────┐  
│ Prediction Result        │  
│ (scan\_result.json)       │  
└──────────────────────────┘

**Design Rule:** ✅ *One PCAP \= One Sample \= One Feature Vector (case-level classification)*

## **Requirements**

* Zeek \>= 5.0  
* Python \>= 3.8

Install Python dependencies:

Bash

pip install \-r requirements.txt

Minimum laboratory versions:

* pandas \>= 2.0  
* numpy \>= 1.24  
* scikit-learn \>= 1.3  
* joblib \>= 1.3

## **Project Structure**

Plaintext

trojan-detection/  
├── build\_zeek\_csvs.sh          \# Zeek analysis \+ CSV export  
├── features\_from\_zeek.py       \# Feature extraction (Zeek CSVs → features)  
├── train\_model.py              \# Model training (Random Forest pipeline)  
├── pcap\_scan.py                \# Scan a new PCAP using the trained model  
├── requirements.txt            \# Python requirements  
├── README.md                   \# Documentation  
│  
├── data/                       \# Training data (PCAPs by class)  
│   ├── rat/  
│   ├── botnet/  
│   ├── downloader/  
│   └── benign/  
│  
└── workspace/                  \# Working directory (generated outputs)  
    ├── zeek\_out/               \# Zeek raw outputs \+ exported CSV logs  
    ├── features\_dataset.csv    \# Final ML dataset (one row per PCAP)  
    ├── scans/                  \# Scan outputs (per PCAP)  
    └── model/                  \# Saved model \+ metadata  
        ├── trojan\_rf.joblib  
        ├── feature\_list.txt  
        └── feature\_importance.csv

## **Quick Start**

1. Run Zeek analysis on data:

Bash

bash build\_zeek\_csvs.sh

**Output:** workspace/zeek\_out/

2. Extract behavioral features:

Bash

python3 features\_from\_zeek.py

**Output:** workspace/features\_dataset.csv

3. Train the classifier:

Bash

python3 train\_model.py

**Output:** workspace/model/ (trojan\_rf.joblib, feature\_list.txt, feature\_importance.csv)

4. Scan a new PCAP file:

Bash

python3 pcap\_scan.py /path/to/sample.pcap

**Output:** workspace/scans/\<pcap\_name\>/scan\_result.json

## **What the Model Learns (Behavioral Features)**

The model relies on statistical network behaviors rather than signature matching:

* Counts  
* Uniques  
* Statistics  
* Ratios/Patterns

## **Outputs & Deliverables**

The pipeline generates the following key artifacts in the workspace/ directory:

* features\_dataset.csv  
* model/trojan\_rf.joblib  
* model/feature\_list.txt  
* model/feature\_importance.csv  
* scans/\*/scan\_result.json

## **Important Notes**

* Feature consistency is critical: training and scanning must use same feature names and order.  
* Any modification to feature extraction requires rebuilding the dataset and retraining the model.