#!/usr/bin/env python3
"""
wazuh_to_defectdojo.py — Final Fixed Version
Sync Wazuh vulnerability findings → DefectDojo

Fix berdasarkan debug output:
  1. agent.id di indexer = "016" (3-digit zero-padded)
     Wazuh API mengembalikan "16" → harus di-zfill(3) sebelum query
  2. score.base = -1.0 saat score.version = "-" → invalid, dibuang
  3. severity = "-" → dibuang
  4. Index hanya satu: wazuh-states-vulnerabilities-baremetal-wazuh
"""

import requests
import json
import time
import logging
import sys
import urllib3
from datetime import datetime, timezone

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===================== CONFIG =====================

WAZUH_API    = "https://$WAZUH_SERVER_IP:55000"
WAZUH_USER   = "wazuh-wui"
WAZUH_PASS   = "$WAZUH_WUI_PASSWORD"

INDEXER_URL  = "https://$WAZUH_SERVER_IP:9200"
INDEXER_USER = "admin"
INDEXER_PASS = "$WAZUH_ADMIN_PASSWORD"
VULN_INDEX   = "wazuh-states-vulnerabilities-*"

DOJO_URL     = "http://$DEFECT_DOJO_SERVER_IP:8080"
DOJO_API_KEY = "Token $DEFECT_DOJO_TOKEN"
PRODUCT_ID   = 1
FOUND_BY_ID  = 1   # cek via: curl http://DOJO/api/v2/test_types/

# agent.id di indexer pakai berapa digit? (lihat debug: "016" = 3 digit)
AGENT_ID_PAD = 3

PAGE_SIZE         = 500   # lebih besar = lebih cepat, aman sampai 1000
SLEEP_PER_AGENT   = 0.3
TIMEOUT           = 30

# ==================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/tmp/wazuh_to_dojo.log", encoding="utf-8")
    ]
)
log = logging.getLogger(__name__)


def iso_today():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# ===================== FIELD EXTRACTION =====================

def extract_score_base(vuln: dict):
    """
    Format di indexer kamu:
      "score": {"base": 5.5, "version": "3.1"}   ← valid
      "score": {"base": -1.0, "version": "-"}     ← INVALID, buang

    Return float jika valid (>= 0), None jika tidak valid.
    """
    s = vuln.get("score", {})
    if not isinstance(s, dict):
        try:
            v = float(s)
            return v if v >= 0 else None
        except Exception:
            return None

    base    = s.get("base")
    version = s.get("version", "")

    # Tandai invalid: version = "-" atau base negatif
    if str(version).strip() == "-":
        return None

    try:
        v = float(base)
        return v if v >= 0 else None
    except Exception:
        return None


def decide_severity(score_base, sev_text):
    """
    Kembalikan (severity_string, score) atau (None, None) untuk Low/invalid.

    Prioritas: CVSS numeric score > severity text.
    Low (< 4.0) dibuang — ubah jika ingin include.
    """
    if score_base is not None:
        if score_base >= 9.0:
            return "Critical", score_base
        if score_base >= 7.0:
            return "High",     score_base
        if score_base >= 4.0:
            return "Medium",   score_base
        return None, None  # Low

    # Fallback ke severity text (hanya jika score tidak tersedia)
    if isinstance(sev_text, str):
        mapping = {
            "critical": ("Critical", 9.5),
            "high":     ("High",     7.5),
            "medium":   ("Medium",   5.0),
        }
        result = mapping.get(sev_text.strip().lower())
        if result:
            return result

    return None, None


# ===================== WAZUH API =====================

def wazuh_auth():
    r = requests.post(
        f"{WAZUH_API}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False, timeout=TIMEOUT
    )
    r.raise_for_status()
    return r.json()["data"]["token"]


def get_agents(token):
    """Ambil semua agent aktif dengan pagination."""
    agents = []
    offset = 0
    limit  = 500
    while True:
        r = requests.get(
            f"{WAZUH_API}/agents?offset={offset}&limit={limit}&status=active",
            headers={"Authorization": f"Bearer {token}"},
            verify=False, timeout=TIMEOUT
        )
        r.raise_for_status()
        data  = r.json()["data"]
        items = data.get("affected_items", [])
        agents.extend(items)
        if len(agents) >= data.get("total_affected_items", 0):
            break
        offset += limit
    return agents


# ===================== INDEXER =====================

def get_vulns_for_agent(agent_id_raw: str):
    """
    agent_id_raw: string dari Wazuh API, misal "16" atau "016"
    Di indexer tersimpan sebagai "016" (zero-padded AGENT_ID_PAD digit).
    Kita query keduanya dengan should untuk aman.
    """
    padded   = agent_id_raw.zfill(AGENT_ID_PAD)   # "16" → "016"
    unpadded = agent_id_raw.lstrip("0") or "0"     # "016" → "16"

    url    = f"{INDEXER_URL}/{VULN_INDEX}/_search"
    search_after = None

    while True:
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"agent.id": padded}},
                        {"term": {"agent.id": unpadded}},
                    ],
                    "minimum_should_match": 1
                }
            },
            "size":  PAGE_SIZE,
            "sort": [
                {"vulnerability.id": "asc"},
                {"_id": "asc"}
            ]
        }

        if search_after:
            query["search_after"] = search_after

        r = requests.post(
            url,
            auth=(INDEXER_USER, INDEXER_PASS),
            headers={"Content-Type": "application/json"},
            data=json.dumps(query),
            verify=False, timeout=TIMEOUT
        )
        r.raise_for_status()

        hits = r.json().get("hits", {}).get("hits", [])
        if not hits:
            break

        for h in hits:
            yield h.get("_source", {})

        if len(hits) < PAGE_SIZE:
            break

        # offset += PAGE_SIZE
        search_after = hits[-1].get("sort")
        if not search_after:
            break


# ===================== DEFECTDOJO =====================

dojo_hdrs = {
    "Authorization": DOJO_API_KEY,
    "Content-Type":  "application/json"
}


def get_or_create_engagement(name: str) -> int:
    r = requests.get(
        f"{DOJO_URL}/api/v2/engagements/",
        params={"product": PRODUCT_ID, "name": name},
        headers=dojo_hdrs, verify=False, timeout=TIMEOUT
    )
    r.raise_for_status()
    res = r.json().get("results", [])
    if res:
        return res[0]["id"]

    payload = {
        "name":            name,
        "product":         PRODUCT_ID,
        "target_start":    iso_today(),
        "target_end":      iso_today(),
        "engagement_type": "CI/CD",
        "status":          "In Progress"
    }
    r = requests.post(
        f"{DOJO_URL}/api/v2/engagements/",
        headers=dojo_hdrs,
        data=json.dumps(payload),
        verify=False, timeout=TIMEOUT
    )
    r.raise_for_status()
    return r.json()["id"]


def get_or_create_test(engagement_id: int, title: str) -> int:
    r = requests.get(
        f"{DOJO_URL}/api/v2/tests/",
        params={"engagement": engagement_id, "title": title},
        headers=dojo_hdrs, verify=False, timeout=TIMEOUT
    )
    r.raise_for_status()
    res = r.json().get("results", [])
    if res:
        return res[0]["id"]

    payload = {
        "title":        title,
        "engagement":   engagement_id,
        "target_start": iso_today(),
        "target_end":   iso_today(),
        "test_type":    FOUND_BY_ID
    }
    r = requests.post(
        f"{DOJO_URL}/api/v2/tests/",
        headers=dojo_hdrs,
        data=json.dumps(payload),
        verify=False, timeout=TIMEOUT
    )
    if not r.ok:
        log.error(f"create_test failed {r.status_code}: {r.text[:300]}")
        r.raise_for_status()
    return r.json()["id"]


def finding_exists(test_id: int, uid: str) -> bool:
    r = requests.get(
        f"{DOJO_URL}/api/v2/findings/",
        params={"test": test_id, "unique_id_from_tool": uid, "limit": 1},
        headers=dojo_hdrs, verify=False, timeout=TIMEOUT
    )
    r.raise_for_status()
    return r.json().get("count", 0) > 0


def cvss_to_numerical_severity(severity_text: str) -> str:
    """
    DefectDojo numerical_severity hanya terima: I, II, III, IV
      I   = Critical
      II  = High
      III = Medium
      IV  = Low
    """
    mapping = {
        "Critical": "I",
        "High":     "II",
        "Medium":   "III",
        "Low":      "IV",
    }
    return mapping.get(severity_text, "III")

def create_finding(test_id: int, f: dict) -> str:
    if finding_exists(test_id, f["uid"]):
        return "exists"

    payload = {
        "title":                f["title"],
        "severity":             f["severity"],
        "numerical_severity":   cvss_to_numerical_severity(f["severity"]),
        "description":          f["description"],
        "active":               True,
        "verified":             False,
        "unique_id_from_tool":  f["uid"],
        "test":                 test_id,
        "found_by":             [FOUND_BY_ID]
    }
    if f.get("cve"):
        payload["cve"] = f["cve"]

    r = requests.post(
        f"{DOJO_URL}/api/v2/findings/",
        headers=dojo_hdrs,
        data=json.dumps(payload),
        verify=False, timeout=TIMEOUT
    )
    if r.status_code in (200, 201):
        return "created"

    log.warning(f"create_finding failed {r.status_code}: {r.text[:300]}")
    return "failed"


# ===================== MAIN =====================

def main():
    log.info("=== wazuh_to_defectdojo STARTED ===")

    token  = wazuh_auth()
    agents = get_agents(token)
    log.info(f"Agents aktif: {len(agents)}")

    grand_created = grand_exists = grand_failed = 0

    for a in agents:
        agent_id   = str(a.get("id", ""))
        agent_name = a.get("name", f"agent-{agent_id}")

        if not agent_id:
            continue

        seen     = set()
        findings = []
        raw_docs = 0
        skipped  = 0

        for doc in get_vulns_for_agent(agent_id):
            raw_docs += 1
            vuln = doc.get("vulnerability", {})

            ident      = vuln.get("id", "").strip()
            score_base = extract_score_base(vuln)
            sev_text   = vuln.get("severity", "")

            sev, cvss = decide_severity(score_base, sev_text)

            if not sev or not ident:
                skipped += 1
                continue

            uid = f"{agent_id}|{ident}"
            if uid in seen:
                continue
            seen.add(uid)

            cve_field = ident if ident.startswith("CVE-") else None

            desc = str(vuln.get("description") or "No description available.")
            ref  = vuln.get("reference", "")
            if ref:
                desc = f"{desc}\n\nReference:\n{ref}"
            if len(desc) > 5000:
                desc = desc[:5000] + "\n\n(truncated)"

            pkg       = doc.get("package", {})
            comp_name = pkg.get("name", "")
            comp_ver  = pkg.get("version", "")

            if comp_name and comp_ver:
                title = f"{ident} in {comp_name} {comp_ver} on {agent_name}"
            else:
                title = f"{ident} on {agent_name}"

            findings.append({
                "title":       title,
                "severity":    sev,
                "cvss":        float(cvss),
                "description": desc,
                "cve":         cve_field,
                "uid":         uid
            })

        log.info(
            f"[{agent_name}] raw={raw_docs} skipped={skipped} "
            f"unique_findings={len(findings)}"
        )

        if not findings:
            time.sleep(0.2)
            continue

        # Push ke DefectDojo
        eng_name = f"Wazuh VA - {agent_name}"
        eng_id   = get_or_create_engagement(eng_name)
        test_id  = get_or_create_test(eng_id, eng_name)

        created = exists = failed = 0
        for f in findings:
            res = create_finding(test_id, f)
            if res == "created":
                created += 1
            elif res == "exists":
                exists += 1
            else:
                failed += 1

        log.info(
            f"[✓] {agent_name}: created={created} "
            f"exists={exists} failed={failed}"
        )
        grand_created += created
        grand_exists  += exists
        grand_failed  += failed

        time.sleep(SLEEP_PER_AGENT)

    log.info(
        f"=== SELESAI === "
        f"total created={grand_created} exists={grand_exists} failed={grand_failed}"
    )


if __name__ == "__main__":
    main()
