#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
features_from_zeek.py - استخراج الميزات من ملفات Zeek CSV
=============================================================================
يقرأ مجلدات workspace/zeek_out/* ويستخرج ميزات سلوكية من:
- conn.csv: إحصائيات الاتصالات، البروتوكولات، الحالات
- dns.csv: استعلامات DNS، الدومينات، الإنتر\وبيا
- http.csv: طلبات HTTP، URIs، User-Agents
- ssl.csv: جلسات TLS/SSL، SNI، التحقق
- files.csv: الملفات المنقولة، MIME types

المخرجات: workspace/features_dataset.csv
=============================================================================
"""

import os
import math
import re
from pathlib import Path
from collections import Counter

import numpy as np
import pandas as pd


# =========================
# إعدادات المسارات
# =========================
ROOT = Path(__file__).resolve().parent
ZEEK_OUT = ROOT / "workspace" / "zeek_out"
OUT_CSV = ROOT / "workspace" / "features_dataset.csv"


# =========================
# أدوات مساعدة
# =========================
def safe_read_csv(p: Path, **kw) -> pd.DataFrame:
    """
    قراءة CSV بشكل آمن مع معالجة الأخطاء
    """
    if not p.exists() or os.path.getsize(p) == 0:
        return pd.DataFrame()
    
    defaults = dict(sep="\t", engine="python", comment="#", on_bad_lines="skip")
    defaults.update(kw)
    
    try:
        df = pd.read_csv(p, **defaults)
        # إزالة الأعمدة المكررة
        if hasattr(df, "columns"):
            df = df.loc[:, ~df.columns.duplicated()]
        return df
    except Exception as e:
        print(f"[!] Error reading {p}: {e}")
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


# =========================
# استخراج الميزات
# =========================
def load_case_features(case_dir: Path) -> dict:
    """
    استخراج جميع الميزات من مجلد حالة واحد
    
    Parameters:
        case_dir: مجلد يحتوي على conn.csv, dns.csv, http.csv, ssl.csv, files.csv
    
    Returns:
        dict: قاموس يحتوي على جميع الميزات المستخرجة
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
        method = http.get("method", pd.Series([], dtype=str)).fillna("").astype(str).str.upper()
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
        suspicious_mime = [
            "application/x-dosexec", "application/x-msdownload", "application/x-msdos-program",
            "application/zip", "application/x-rar-compressed", "application/octet-stream",
            "application/vnd.ms-cab-compressed"
        ]
        feats["percent_exe_zip"] = ratio(sum(any(k in m for k in suspicious_mime) for m in mime), len(mime))
    else:
        feats["uniq_mime_types"] = 0
        feats["percent_exe_zip"] = 0.0
    
    return feats


def infer_label_from_dir(d: Path) -> str:
    """استنتاج التصنيف من اسم المجلد أو ملف label.txt"""
    name = d.name
    
    # محاولة الاستنتاج من اسم المجلد
    if name.startswith("rat_"):
        return "rat"
    if name.startswith("downloader_"):
        return "downloader"
    if name.startswith("botnet_"):
        return "botnet"
    if name.startswith("benign_"):
        return "benign"
    
    # محاولة القراءة من label.txt
    labfile = d / "label.txt"
    if labfile.exists():
        try:
            return labfile.read_text().strip()
        except Exception:
            pass
    
    return "unknown"


# =========================
# MAIN
# =========================
def main():
    print("=" * 70)
    print("Feature Extraction from Zeek Logs")
    print("=" * 70)
    
    if not ZEEK_OUT.exists():
        print(f"[!] Error: {ZEEK_OUT} not found")
        print("    Please run build_zeek_csvs.sh first")
        return 1
    
    case_dirs = sorted([p for p in ZEEK_OUT.iterdir() if p.is_dir()])
    
    if not case_dirs:
        print(f"[!] Error: No case directories found in {ZEEK_OUT}")
        return 1
    
    print(f"[*] Found {len(case_dirs)} case directories")
    print(f"[*] Extracting features...")
    
    rows = []
    for i, c in enumerate(case_dirs, 1):
        try:
            print(f"    [{i}/{len(case_dirs)}] {c.name}")
            feats = load_case_features(c)
            feats["label"] = infer_label_from_dir(c)
            rows.append(feats)
        except Exception as e:
            print(f"    [!] Error processing {c.name}: {e}")
    
    if not rows:
        print("[!] Error: No features extracted")
        return 1
    
    # إنشاء DataFrame
    df = pd.DataFrame(rows)
    
    # ترتيب الأعمدة
    preferred_order = [
        "label",
        "flows_total", "flows_tcp", "flows_udp", "uniq_dst_ips", "uniq_dst_ports",
        "dur_mean", "dur_std", "dur_p95",
        "flows_dns", "flows_http", "flows_ssl",
        "state_ratio_S0", "state_ratio_S1", "state_ratio_SF", "state_ratio_REJ",
        "state_ratio_RSTO", "state_ratio_RSTR", "state_ratio_SH", "state_ratio_OTH",
        "orig_bytes_mean", "orig_bytes_p95", "resp_bytes_mean", "resp_bytes_p95", "bytes_ratio_mean",
        "dns_queries_total", "uniq_domains", "uniq_qtypes",
        "percent_numeric_subdomains", "percent_single_label_domains", "percent_long_labels",
        "avg_answers_per_query",
        "http_req_total", "http_post_count", "http_get_count",
        "uniq_hosts", "uniq_uris", "avg_uri_len", "max_uri_len",
        "uniq_user_agents", "ua_entropy_approx", "post_ratio", "suspicious_path_ratio",
        "tls_sessions", "uniq_sni", "no_sni_ratio", "percent_invalid_validation",
        "files_seen", "uniq_mime_types", "percent_exe_zip",
        "top1_dst_ratio", "top3_dst_ratio",
        "beacon_jitter_mean", "beacon_pairs_ge3",
        "long_80443_ratio",
        "top1_sni_ratio", "sni_len_mean", "sni_entropy_mean",
        "domain_len_mean", "domain_entropy_mean",
    ]
    
    cols = [c for c in preferred_order if c in df.columns] + [c for c in df.columns if c not in preferred_order]
    df = df[cols]
    
    # حفظ النتيجة
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_CSV, index=False)
    
    print("\n" + "=" * 70)
    print("Feature Extraction Complete!")
    print("=" * 70)
    print(f"Output file: {OUT_CSV}")
    print(f"Dataset shape: {df.shape}")
    print(f"Features: {df.shape[1] - 1}")  # -1 for label column
    print(f"Samples: {df.shape[0]}")
    print("\nClass distribution:")
    for cls, count in df["label"].value_counts().items():
        print(f"  {cls:12s}: {count:4d} ({count/len(df):.1%})")
    print("\nNext step:")
    print("  Run: python3 train_model.py")
    print("=" * 70)
    
    return 0


if __name__ == "__main__":
    exit(main())
