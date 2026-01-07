# **🛡️ AI-Driven Trojan Detection Using Network Traffic Analysis**

### ***Graduation Project 2025 — Yarmouk University***

**Project:** AI-Based Malware Detection (PCAP → Zeek → Machine Learning)

**App Type:** Streamlit Web Application (Dark Theme)

**Target:** Detection of RAT, Downloader, Botnet, and Benign behaviors in encrypted/network traffic.

## ---

**📋 Overview**

This project is a cybersecurity tool designed to detect **Trojan malware behaviors** by analyzing network traffic (**PCAP/PCAPNG**) rather than host-based artifacts. It leverages the **Zeek Network Security Monitor** to extract protocol-agnostic logs and applies a trained **Random Forest** model to classify traffic patterns.

**Key capabilities:**

* \*\* Automated Analysis:\*\* Upload a PCAP and get instant classification results.  
* \*\* Feature Extraction:\*\* Parsing of conn, dns, http, and ssl logs into behavioral features (Flow stats, DNS entropy, Beaconing jitter, etc.).  
* \*\* Visual Reporting:\*\* Interactive charts, probability tables, and HTML report generation.  
* \*\* Privacy-Preserving:\*\* Operates on traffic metadata (logs), not deep packet inspection of payloads.

## ---

**🏗️ System Architecture**

The application follows a linear data processing pipeline:

مقتطف الرمز

┌───────────────┐  
│  PCAP Input   │  (User Upload)  
└───────┬───────┘  
        │  
        ▼  
┌───────────────────────────┐  
│   Zeek Traffic Analysis   │  (Generates conn.log, dns.log...)  
└───────────┬───────────────┘  
            │  
            ▼  
┌───────────────────────────┐  
│     Log Parsing (CSV)     │  (zeek-cut conversion)  
└───────────┬───────────────┘  
            │  
            ▼  
┌───────────────────────────┐  
│    Feature Extraction     │  (Python / Pandas)  
└───────────┬───────────────┘  
            │  
            ▼  
┌───────────────────────────┐  
│   ML Model Inference      │  (RandomForest .joblib)  
└───────────┬───────────────┘  
            │  
            ▼  
┌───────────────────────────┐  
│   Streamlit Dashboard     │  (Results, Charts, Reports)  
└───────────────────────────┘

## ---

**📂 Project Structure**

Plaintext

trojan-webapp/  
├── app.py                   \# Main Streamlit application entry point  
├── README.md                \# Project documentation  
├── .venv/                   \# Python virtual environment  
│  
├── model/  
│   └── trojan\_rf.joblib     \# Pre-trained Random Forest model  
│  
├── assets/  
│   └── yarmouk\_logo.png     \# University branding (optional)  
│  
├── workspace/               \# Dynamic analysis output folder  
│   └── \<case\_id\>/           \# Unique ID per analysis  
│       ├── uploaded.pcap  
│       ├── conn.log, dns.log...  
│       ├── conn.csv, dns.csv...  
│       └── features.csv  
│  
└── features\_from\_zeek.py    \# (External dependency imported via sys.path)

## ---

**🔧 Requirements & Compatibility**

To ensure the saved model loads correctly without binary errors, specific library versions are required.

### **System Requirements**

* **OS:** Linux (Debian/Ubuntu/Kali/Parrot)  
* **Python:** 3.10+ (tested on 3.11)  
* **Zeek:** Version 5.x or higher (verify with zeek \-v)

### **Python Dependencies (Pinned)**

Plaintext

numpy==1.26.4  
scipy==1.11.4  
scikit-learn==1.2.2  
pandas  
streamlit  
joblib  
matplotlib

## ---

**🚀 Setup & Installation**

### **1\. Prepare the Environment**

Open your terminal in the project directory:

Bash

\# Create a virtual environment  
python3 \-m venv .venv

\# Activate the environment  
source .venv/bin/activate

### **2\. Install Dependencies**

Install the strictly pinned versions to match the training environment:

Bash

\# Update pip first  
python \-m pip install \--upgrade pip

\# Install critical ML libraries  
python \-m pip install "numpy==1.26.4" "scipy==1.11.4" "scikit-learn==1.2.2"

\# Install app framework and utilities  
python \-m pip install streamlit pandas joblib matplotlib

### **3\. Verify Assets**

Ensure your model file exists:

Bash

ls \-l model/trojan\_rf.joblib

## ---

**🖥️ How to Run**

### **Local Execution (Inside VM)**

Run the Streamlit app:

Bash

\# (Optional) Pre-compile to check for syntax errors  
python \-m py\_compile app.py

\# Launch the app  
python \-m streamlit run app.py

Access the app at: **http://localhost:8501**

### **Accessing from Host Machine (Outside VM)**

If running inside a Virtual Machine (e.g., VirtualBox/VMware), use one of these methods to view the app on your host browser.

**Method A: Bridged Networking (Recommended)**

1. Run with global binding:  
   Bash  
   python \-m streamlit run app.py \--server.address 0.0.0.0

2. Find your VM's IP address:  
   Bash  
   ip a

3. Open browser on Host: http://\<VM\_IP\_ADDRESS\>:8501

**Method B: NAT Port Forwarding**

1. Configure VM Network Settings: Forward Host Port 8501 to Guest Port 8501\.  
2. Run the app normally.  
3. Open browser on Host: http://127.0.0.1:8501

## ---

**🧪 Usage Guide**

1. **Upload:** Drag and drop a .pcap or .pcapng file into the upload widget.  
2. **Analyze:** Click the **"Run Analysis"** button. The spinner indicates that Zeek is parsing logs and features are being extracted.  
3. **View Results:**  
   * **Prediction:** See the classified malware family (or Benign).  
   * **Confidence:** View the probability bar chart.  
   * **Features:** Inspect the calculated network features (e.g., flows\_total, dns\_entropy).  
4. **Export:**  
   * Go to the **"Report"** tab to download a full HTML report.  
   * Use the sidebar to download raw CSV data.

## ---

**🐛 Troubleshooting**

| Issue | Solution |
| :---- | :---- |
| **streamlit: command not found** | Ensure your virtual environment is activated: source .venv/bin/activate |
| **Zeek not found** | Ensure Zeek is installed and in your system PATH (zeek \-v). |
| **ValueError: node array from the pickle...** | You have a scikit-learn version mismatch. Run: pip install scikit-learn==1.2.2 |
| **FileNotFoundError: model/trojan\_rf.joblib** | The model file is missing. Place the .joblib file in the model/ directory. |

## ---

**🔒 Security & Disclaimer**

* **Sandboxing:** Always run analysis of potential malware PCAPs inside an isolated Virtual Machine.  
* **Privacy:** This tool processes traffic logs. Ensure you have authorization to capture and analyze the network traffic submitted.  
* **Accuracy:** While the Random Forest model is highly accurate, false positives are possible. Use results as an indicator, not a guarantee.

## ---

**📚 References**

* [Zeek Network Security Monitor Documentation](https://docs.zeek.org/)  
* [Scikit-Learn Random Forest Classifier](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html)  
* [Streamlit Documentation](https://docs.streamlit.io/)