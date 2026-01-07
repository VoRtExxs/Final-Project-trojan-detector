#!/usr/bin/env python3
"""
يفحص ملف PCAP واحد ويتنبأ بنوع التهديد
"""
import argparse
import json
import math
import os
import subprocess
from pathlib import Path
from collections import Counter

import pandas as pd
import numpy as np
import joblib

# ========= إعدادات المسارات =========
ROOT = Path(__file__).resolve().parent
WORK = ROOT / "workspace"
SCANS = WORK / "scans"
MODEL_PATH = WORK / "model" / "trojan_rf.joblib"
FEATURE_LIST_PATH = WORK / "model" / "feature_list.txt"


# ========= أدوات مساعدة =========
def run_command(cmd: list, cwd=None):
    """تشغيل أمر بشكل آمن"""
    print(f"[>] {' '.join(cmd)}")
    try:
        subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {e.stderr}")
        raise


def check_zeek_installed():
    """التحقق من تثبيت Zeek"""
    try:
        subprocess.run(["zeek", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        raise SystemExit("[!] Zeek is not installed. Please install it first.")


def zeek_to_csvs(out_dir: Path):
    """تحويل لوجات Zeek إلى CSV نظيفة"""
    conversions = [
        ("conn.log", "conn.csv", ["ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", 
                                   "proto", "service", "duration", "conn_state", "orig_bytes", "resp_bytes"]),
        ("dns.log", "dns.csv", ["ts", "uid", "id.orig_h", "id.resp_h", "query", "answers", "qtype"]),
        ("http.log", "http.csv", ["ts", "uid", "id.orig_h", "id.resp_h", "http.method", 
                                   "host", "uri", "user_agent", "status_code"]),
        ("ssl.log", "ssl.csv", ["ts", "uid", "id.orig_h", "id.resp_h", "id.resp_p", 
                                 "server_name", "established", "validation_status"]),
        ("files.log", "files.csv", ["ts", "uid", "id.orig_h", "id.resp_h", 
                                     "filename", "mime_type", "sha256"]),
    ]
    
    for log_file, csv_file, fields in conversions:
        log_path = out_dir / log_file
        csv_path = out_dir / csv_file
        
        # محاولة ssl.log أو tls.log
        if log_file == "ssl.log" and not log_path.exists():
            log_path = out_dir / "tls.log"
        
        if log_path.exists() and log_path.stat().st_size > 0:
            try:
                cmd = ["zeek-cut", "-c"] + fields
                with log_path.open("rb") as fin, csv_path.open("wb") as fout:
                    subprocess.run(cmd, stdin=fin, stdout=fout, check=True)
            except subprocess.CalledProcessError:
                print(f"[!] Failed to convert {log_file}")


def safe_read_csv(path: Path) -> pd.DataFrame:
    """قراءة CSV بشكل آمن"""
    if not path.exists() or path.stat().st_size == 0:
        return pd.DataFrame()
    try:
        return pd.read_csv(path, sep="\t", engine="python", comment="#", on_bad_lines="skip")
    except Exception as e:
        print(f"[!] Error reading {path}: {e}")
        return pd.DataFrame()


def ratio(num, den):
    """حساب النسبة بأمان"""
    num = float(num) if num else 0.0
    den = float(den) if den else 0.0
    return (num / den) if den > 0 else 0.0


def approx_entropy_str(s: str) -> float:
    """حساب الإنتروبيا التقريبية لسلسلة نصية"""
    if not isinstance(s, str) or not s:
        return 0.0
    cnt = Counter(s)
    total = sum(cnt.values())
    if total == 0:
        return 0.0
    ent = 0.0
    for c, n in cnt.items():
        p = n / total
        if p > 0:
            ent -= p * math.log2(p)
    return float(ent)


def to_float_series(x: pd.Series) -> pd.Series:
    """تحويل إلى float بأمان"""
    if x is None or len(x) == 0:
        return pd.Series([], dtype=float)
    return pd.to_numeric(x, errors="coerce").fillna(0.0).astype(float)


def to_int_series(x: pd.Series) -> pd.Series:
    """تحويل إلى int بأمان"""
    if x is None or len(x) == 0:
        return pd.Series([], dtype=int)
    return pd.to_numeric(x, errors="coerce").fillna(0).astype(int)


# ========= استخراج الخصائص (متطابق مع features_from_zeek.py) =========
def compute_features(case_dir: Path) -> dict:
    """
    استخراج جميع الخصائص من ملفات Zeek CSV
    يجب أن يكون متطابقاً 100% مع features_from_zeek.py
    """
    feats = {}
    
    # قراءة جميع الملفات
    conn = safe_read_csv(case_dir / "conn.csv")
    dns = safe_read_csv(case_dir / "dns.csv")
    http = safe_read_csv(case_dir / "http.csv")
    ssl = safe_read_csv(case_dir / "ssl.csv")
    files = safe_read_csv(case_dir / "files.csv")
    
    # ========= CONN FEATURES =========
    feats["flows_total"] = len(conn)
    
    if len(conn):
        proto = conn.get("proto", pd.Series([], dtype=str)).fillna("").astype(str).str.lower()
        feats["flows_tcp"] = int((proto == "tcp").sum())
        feats["flows_udp"] = int((proto == "udp").sum())
        
        dst_ip = conn.get("id.resp_h", pd.Series([], dtype=str)).fillna("").astype(str)
        dst_port = to_int_series(conn.get("id.resp_p", pd.Series([], dtype=str)))
        
        feats["uniq_dst_ips"] = int(dst_ip.nunique(dropna=True))
        feats["uniq_dst_ports"] = int(dst_port.replace(0, np.nan).nunique(dropna=True))
        
        dur = to_float_series(conn.get("duration", pd.Series([], dtype=float)))
        feats["dur_mean"] = float(dur.mean()) if len(dur) else 0.0
        feats["dur_std"] = float(dur.std()) if len(dur) else 0.0
        feats["dur_p95"] = float(dur.quantile(0.95)) if len(dur) else 0.0
        
        st = conn.get("conn_state", pd.Series([], dtype=str)).fillna("").astype(str)
        st_counts = st.value_counts()
        total = max(1, len(st))
        for sname in ["S0", "S1", "SF", "REJ", "RSTO", "RSTR", "SH", "OTH"]:
            feats[f"state_ratio_{sname}"] = float(st_counts.get(sname, 0) / total)
        
        ob = to_float_series(conn.get("orig_bytes", pd.Series([], dtype=float)))
        rb = to_float_series(conn.get("resp_bytes", pd.Series([], dtype=float)))
        feats["orig_bytes_mean"] = float(ob.mean()) if len(ob) else 0.0
        feats["orig_bytes_p95"] = float(ob.quantile(0.95)) if len(ob) else 0.0
        feats["resp_bytes_mean"] = float(rb.mean()) if len(rb) else 0.0
        feats["resp_bytes_p95"] = float(rb.quantile(0.95)) if len(rb) else 0.0
        
        ob_safe = ob.replace(0, np.nan)
        ratio_series = (rb / ob_safe).replace([np.inf, -np.inf], np.nan).fillna(0.0)
        feats["bytes_ratio_mean"] = float(ratio_series.mean()) if len(ratio_series) else 0.0
        
        # تركّز الوجهات
        if len(dst_ip):
            counts = dst_ip.value_counts()
            total_flows = len(dst_ip)
            feats["top1_dst_ratio"] = float((counts.iloc[0] / total_flows) if len(counts) else 0.0)
            feats["top3_dst_ratio"] = float((counts.iloc[:3].sum() / total_flows) if len(counts) >= 3 else feats["top1_dst_ratio"])
        else:
            feats["top1_dst_ratio"] = 0.0
            feats["top3_dst_ratio"] = 0.0
        
        # Beaconing jitter
        ts = to_float_series(conn.get("ts", pd.Series([], dtype=float)))
        beacon_pairs_ge3 = 0
        jitters = []
        if len(ts) and len(dst_ip) and len(dst_port):
            df_ts = pd.DataFrame({"ts": ts, "ip": dst_ip, "port": dst_port})
            for (ip, port), g in df_ts.groupby(["ip", "port"]):
                g = g.sort_values("ts")
                if len(g) < 3:
                    continue
                diffs = np.diff(g["ts"].values)
                if len(diffs) >= 2 and diffs.mean() > 0:
                    beacon_pairs_ge3 += 1
                    cv = float(diffs.std() / diffs.mean()) if diffs.mean() else 0.0
                    jitters.append(cv)
        feats["beacon_jitter_mean"] = float(np.mean(jitters)) if jitters else 0.0
        feats["beacon_pairs_ge3"] = int(beacon_pairs_ge3)
        
        # جلسات طويلة على 80/443
        mask_ports = dst_port.isin([80, 443])
        long_mask = (dur > 60) & mask_ports if len(dur) else pd.Series([], dtype=bool)
        feats["long_80443_ratio"] = float(long_mask.mean()) if len(dur) else 0.0
    else:
        feats["flows_tcp"] = feats["flows_udp"] = 0
        feats["uniq_dst_ips"] = feats["uniq_dst_ports"] = 0
        feats["dur_mean"] = feats["dur_std"] = feats["dur_p95"] = 0.0
        for sname in ["S0", "S1", "SF", "REJ", "RSTO", "RSTR", "SH", "OTH"]:
            feats[f"state_ratio_{sname}"] = 0.0
        feats["orig_bytes_mean"] = feats["orig_bytes_p95"] = 0.0
        feats["resp_bytes_mean"] = feats["resp_bytes_p95"] = 0.0
        feats["bytes_ratio_mean"] = 0.0
        feats["top1_dst_ratio"] = feats["top3_dst_ratio"] = 0.0
        feats["beacon_jitter_mean"] = 0.0
        feats["beacon_pairs_ge3"] = 0
        feats["long_80443_ratio"] = 0.0
    
    # ========= DNS FEATURES =========
    feats["flows_dns"] = len(dns)
    if len(dns):
        qnames = dns.get("query", pd.Series([], dtype=str)).fillna("").astype(str)
        feats["dns_queries_total"] = int(len(qnames))
        feats["uniq_domains"] = int(qnames.nunique(dropna=True))
        qtypes = dns.get("qtype", pd.Series([], dtype=str)).fillna("").astype(str)
        feats["uniq_qtypes"] = int(qtypes.nunique(dropna=True))
        
        def is_numeric_sub(s):
            parts = s.split(".")
            subs = [p for p in parts if p]
            if not subs:
                return False
            head = subs[0]
            return head.isdigit() and len(head) >= 6
        
        def long_label(s):
            parts = s.split(".")
            return any(len(p) >= 20 for p in parts if p)
        
        feats["percent_numeric_subdomains"] = ratio(sum(is_numeric_sub(s) for s in qnames), len(qnames))
        feats["percent_single_label_domains"] = ratio(sum("." not in s for s in qnames), len(qnames))
        feats["percent_long_labels"] = ratio(sum(long_label(s) for s in qnames), len(qnames))
        
        feats["domain_len_mean"] = float(pd.Series([len(x) for x in qnames]).mean())
        feats["domain_entropy_mean"] = float(pd.Series([approx_entropy_str(x) for x in qnames]).mean())
        
        if "answers" in dns:
            ans_counts = dns["answers"].fillna("").apply(lambda s: 0 if s == "" else len([a for a in str(s).split(",") if a]))
            feats["avg_answers_per_query"] = float(ans_counts.mean())
        else:
            feats["avg_answers_per_query"] = 0.0
    else:
        feats["dns_queries_total"] = 0
        feats["uniq_domains"] = feats["uniq_qtypes"] = 0
        feats["percent_numeric_subdomains"] = 0.0
        feats["percent_single_label_domains"] = 0.0
        feats["percent_long_labels"] = 0.0
        feats["domain_len_mean"] = 0.0
        feats["domain_entropy_mean"] = 0.0
        feats["avg_answers_per_query"] = 0.0
    
    # ========= HTTP FEATURES =========
    feats["http_req_total"] = len(http)
    if len(http):
        method = http.get("http.method", pd.Series([], dtype=str)).fillna("").astype(str).str.upper()
        feats["http_post_count"] = int((method == "POST").sum())
        feats["http_get_count"] = int((method == "GET").sum())
        feats["post_ratio"] = ratio(feats["http_post_count"], feats["http_req_total"])
        
        host = http.get("host", pd.Series([], dtype=str)).fillna("").astype(str)
        uri = http.get("uri", pd.Series([], dtype=str)).fillna("").astype(str)
        ua = http.get("user_agent", pd.Series([], dtype=str)).fillna("").astype(str)
        
        feats["uniq_hosts"] = int(host.nunique(dropna=True))
        feats["uniq_uris"] = int(uri.nunique(dropna=True))
        uri_len = pd.Series([len(x) for x in uri], dtype=float)
        feats["avg_uri_len"] = float(uri_len.mean()) if len(uri_len) else 0.0
        feats["max_uri_len"] = float(uri_len.max()) if len(uri_len) else 0.0
        feats["uniq_user_agents"] = int(ua.nunique(dropna=True))
        feats["ua_entropy_approx"] = float(pd.Series([approx_entropy_str(x) for x in ua]).mean())
        
        sus_patterns = [
            "..", "%00", "/wp-admin", "/admin", "/login", "cmd=", "powershell",
            ".exe", ".vbs", ".php", ".asp", ".aspx", ".jsp", ".jar", ".rar", ".zip",
            "/shell", "/cmd", "/bin/sh", "base64,"
        ]
        if len(uri):
            sus_count = sum(any(pat in u.lower() for pat in sus_patterns) for u in uri)
            feats["suspicious_path_ratio"] = ratio(sus_count, len(uri))
        else:
            feats["suspicious_path_ratio"] = 0.0
    else:
        feats["http_post_count"] = feats["http_get_count"] = 0
        feats["post_ratio"] = 0.0
        feats["uniq_hosts"] = feats["uniq_uris"] = 0
        feats["avg_uri_len"] = feats["max_uri_len"] = 0.0
        feats["uniq_user_agents"] = 0
        feats["ua_entropy_approx"] = 0.0
        feats["suspicious_path_ratio"] = 0.0
    
    # ========= SSL/TLS FEATURES =========
    feats["flows_ssl"] = len(ssl)
    if len(ssl):
        sni = ssl.get("server_name", pd.Series([], dtype=str)).fillna("").astype(str)
        feats["uniq_sni"] = int(sni.replace("", np.nan).nunique(dropna=True))
        feats["no_sni_ratio"] = ratio(sum(s.strip() == "" for s in sni), len(sni))
        
        validation = ssl.get("validation_status", pd.Series([], dtype=str)).fillna("").astype(str).str.lower()
        bad_val = sum(v not in ["", "ok", "self signed certificate"] and "ok" not in v for v in validation)
        feats["percent_invalid_validation"] = ratio(bad_val, len(validation))
        
        sni_counts = sni.replace("", np.nan).dropna().value_counts()
        feats["top1_sni_ratio"] = float((sni_counts.iloc[0] / len(sni)) if len(sni_counts) else 0.0)
        feats["sni_len_mean"] = float(pd.Series([len(x) for x in sni if isinstance(x, str)]).mean()) if len(sni) else 0.0
        feats["sni_entropy_mean"] = float(pd.Series([approx_entropy_str(x) for x in sni]).mean())
        
        feats["tls_sessions"] = int(len(ssl))
    else:
        feats["uniq_sni"] = 0
        feats["no_sni_ratio"] = 0.0
        feats["percent_invalid_validation"] = 0.0
        feats["top1_sni_ratio"] = 0.0
        feats["sni_len_mean"] = 0.0
        feats["sni_entropy_mean"] = 0.0
        feats["tls_sessions"] = 0
    
    # ========= FILES FEATURES =========
    feats["files_seen"] = int(len(files))
    if len(files):
        mime = files.get("mime_type", pd.Series([], dtype=str)).fillna("").astype(str).str.lower()
        feats["uniq_mime_types"] = int(mime.replace("", np.nan).nunique(dropna=True))
        suspicious_mime = ["application/x-dosexec", "application/x-msdownload", "application/x-msdos-program",
                           "application/zip", "application/x-rar-compressed", "application/octet-stream",
                           "application/vnd.ms-cab-compressed"]
        feats["percent_exe_zip"] = ratio(sum(any(k in m for k in suspicious_mime) for m in mime), len(mime))
    else:
        feats["uniq_mime_types"] = 0
        feats["percent_exe_zip"] = 0.0
    
    return feats


# ========= MAIN =========
def main():
    parser = argparse.ArgumentParser(description="Scan a PCAP file for Trojan detection")
    parser.add_argument("pcap", help="Path to PCAP file")
    parser.add_argument("--output", "-o", help="Output JSON file path", default=None)
    args = parser.parse_args()
    
    # التحقق من Zeek
    check_zeek_installed()
    
    # التحقق من النموذج
    if not MODEL_PATH.exists():
        raise SystemExit(f"[!] Model not found: {MODEL_PATH}\nPlease train the model first with train_model.py")
    
    if not FEATURE_LIST_PATH.exists():
        raise SystemExit(f"[!] Feature list not found: {FEATURE_LIST_PATH}")
    
    # التحقق من ملف PCAP
    pcap = Path(args.pcap).resolve()
    if not pcap.exists():
        raise SystemExit(f"[!] PCAP file not found: {pcap}")
    
    # إنشاء مجلد الإخراج
    out_dir = SCANS / pcap.stem
    out_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"[*] Analyzing: {pcap}")
    print(f"[*] Output directory: {out_dir}")
    
    # تشغيل Zeek
    print("[*] Running Zeek analysis...")
    run_command(["zeek", "-Cr", str(pcap)], cwd=out_dir)
    
    # تحويل اللوجات إلى CSV
    print("[*] Converting logs to CSV...")
    zeek_to_csvs(out_dir)
    
    # استخراج الخصائص
    print("[*] Extracting features...")
    feats = compute_features(out_dir)
    
    # قراءة ترتيب الخصائص من feature_list.txt
    feature_names = FEATURE_LIST_PATH.read_text().strip().split(",")
    feature_names = [f.strip() for f in feature_names if f.strip()]
    
    # بناء DataFrame بالترتيب الصحيح
    row = {k: float(feats.get(k, 0.0)) for k in feature_names}
    X = pd.DataFrame([row], columns=feature_names)
    
    # تحميل النموذج والتنبؤ
    print("[*] Loading model and predicting...")
    pipe = joblib.load(MODEL_PATH)
    proba = pipe.predict_proba(X)[0]
    classes = list(pipe.named_steps["clf"].classes_)
    pred = classes[int(proba.argmax())]
    conf = float(max(proba))
    
    # إعداد النتيجة
    result = {
        "pcap": str(pcap),
        "prediction": pred,
        "confidence": conf,
        "probabilities": {cls: float(p) for cls, p in zip(classes, proba)},
        "features_extracted": len(feats),
        "output_dir": str(out_dir)
    }
    
    # حفظ النتيجة
    output_path = Path(args.output) if args.output else (out_dir / "scan_result.json")
    output_path.write_text(json.dumps(result, indent=2))
    
    # طباعة النتيجة
    print("\n" + "="*60)
    print("SCAN RESULT")
    print("="*60)
    print(f"PCAP File:    {pcap.name}")
    print(f"Prediction:   {pred.upper()}")
    print(f"Confidence:   {conf:.2%}")
    print("\nClass Probabilities:")
    for cls, p in zip(classes, proba):
        print(f"  {cls:12s}: {p:.2%} {'█' * int(p * 50)}")
    print("="*60)
    print(f"\n[*] Results saved to: {output_path}")


if __name__ == "__main__":
    main()
