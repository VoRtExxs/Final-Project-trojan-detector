#!/usr/bin/env bash
set -euo pipefail

DATA_DIR="data"
OUT_DIR="workspace/zeek_out"
mkdir -p "$OUT_DIR"

process_pcap() {
  label="$1"; pcap="$2"
  base="$(basename "$pcap" .pcap)"
  case_dir="$OUT_DIR/${label}_${base}"
  mkdir -p "$case_dir"
  echo "[*] Processing $pcap => $case_dir"

  (cd "$case_dir" && zeek -Cr "$pcap" || { echo "Zeek failed on $pcap"; return 0; })

  (cd "$case_dir" && {
    zeek-cut -c id.orig_h id.orig_p id.resp_h id.resp_p proto service duration conn_state orig_bytes resp_bytes < conn.log > conn.csv 2>/dev/null || echo "conn.log missing"
    zeek-cut -c ts uid id.orig_h id.resp_h query answers qtype < dns.log > dns.csv 2>/dev/null || echo "dns.log missing"
    zeek-cut -c ts uid id.orig_h id.resp_h http.method host uri user_agent status_code < http.log > http.csv 2>/dev/null || echo "http.log missing"
    zeek-cut -c ts uid id.orig_h id.resp_h id.resp_p server_name established validation_status < ssl.log > ssl.csv 2>/dev/null \
      || zeek-cut -c ts uid id.orig_h id.resp_h id.resp_p server_name established validation_status < tls.log > ssl.csv 2>/dev/null \
      || echo "ssl/tls log missing"
    zeek-cut -c ts uid id.orig_h id.resp_h filename mime_type sha256 < files.log > files.csv 2>/dev/null || echo "files.log missing"
  })

  echo "$label" > "$case_dir/label.txt"
}

export -f process_pcap

for label in rat botnet downloader benign; do
  find "$DATA_DIR/$label" -name "*.pcap" -print0 | while IFS= read -r -d '' p; do
    process_pcap "$label" "$(realpath "$p")"
  done
done

echo "[*] Done."
