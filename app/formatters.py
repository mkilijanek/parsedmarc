from __future__ import annotations

import csv
import io
import json
import time
from datetime import datetime, timezone
from typing import Iterable, Dict, Any, List

from .models import Indicator

# Helpers
def _utc_iso(dt: datetime | None) -> str:
    if dt is None:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')

def _sanitize_name(s: str) -> str:
    # For tool formats that need a name identifier
    return s.replace('.', '-').replace(':', '-').replace('/', '-').replace('\\', '-')

def _only_ip(ind: Indicator) -> bool:
    return ind.type == "ip"


def _ip_or_all(indicators: Iterable[Indicator]) -> List[Indicator]:
    rows = [i for i in indicators if _only_ip(i)]
    return rows if rows else list(indicators)

def _severity_from_confidence(conf: int) -> str:
    if conf >= 85: return "high"
    if conf >= 65: return "medium"
    return "low"

def _tlp_lower(tlp: str) -> str:
    return (tlp or "GREEN").lower()


def _json_pretty(payload: Any) -> str:
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _json_compact(payload: Any) -> str:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

def export_txt(indicators: Iterable[Indicator]) -> str:
    # One per line: value
    out = []
    for ind in indicators:
        out.append(ind.value)
    return "\n".join(out) + ("\n" if out else "")

def export_csv(indicators: Iterable[Indicator]) -> str:
    # Generic CSV
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["value","type","confidence","tlp","source","source_id","is_active","tags"])
    for ind in indicators:
        w.writerow([ind.value, ind.type, ind.confidence, ind.tlp, ind.source, ind.source_id or "", ind.is_active, ";".join(ind.tags or [])])
    return buf.getvalue()

def export_json(indicators: Iterable[Indicator]) -> str:
    payload = [
        {
            "value": ind.value,
            "type": ind.type,
            "confidence": ind.confidence,
            "tlp": ind.tlp,
            "source": ind.source,
            "source_id": ind.source_id,
            "is_active": ind.is_active,
            "tags": ind.tags or [],
            "metadata": ind.metadata_ or {},
            "first_seen": _utc_iso(ind.first_seen),
            "last_seen": _utc_iso(ind.last_seen),
        }
        for ind in indicators
    ]
    return _json_pretty(payload)

def export_xml(indicators: Iterable[Indicator]) -> str:
    # Minimal XML suitable for ingestion pipelines; not vendor-specific
    from xml.sax.saxutils import escape
    items = []
    for ind in indicators:
        items.append(
            f"<indicator><value>{escape(ind.value)}</value><type>{escape(ind.type)}</type><confidence>{ind.confidence}</confidence><tlp>{escape(ind.tlp)}</tlp><source>{escape(ind.source)}</source></indicator>"
        )
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<indicators>" + "".join(items) + "</indicators>\n"

# 4.1 FortiGate (External Block List)
def export_fortigate_ebl(indicators: Iterable[Indicator]) -> str:
    return export_txt(_ip_or_all(indicators))

# 4.2 FortiGate IPS
def export_fortigate_ips(indicators: Iterable[Indicator]) -> str:
    out = []
    sig_id = 90000000
    for idx, ind in enumerate(_ip_or_all(indicators)):
        threat_name = f"ThreatFeed-{idx}"
        severity = "high" if ind.confidence >= 65 else "medium"
        line = f"{threat_name}|{sig_id+idx}|{severity}|tcp|{ind.value}|any|any|any"
        out.append(line)
    return "\n".join(out) + ("\n" if out else "")

# 4.3 Check Point (CSV Import)
def export_checkpoint_csv(indicators: Iterable[Indicator]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["name","ip-address","confidence","severity","comments","color"])
    for ind in _ip_or_all(indicators):
        name = f"ThreatFeed-{_sanitize_name(ind.value)}"
        conf = "high" if ind.confidence >= 80 else "medium" if ind.confidence >= 60 else "low"
        sev = _severity_from_confidence(ind.confidence)
        color = "red" if sev == "high" else "orange" if sev == "medium" else "yellow"
        w.writerow([name, ind.value, conf, sev, "Threat intelligence indicator", color])
    return buf.getvalue()

# 4.4 Palo Alto Networks (EDL)
def export_paloalto_edl(indicators: Iterable[Indicator]) -> str:
    out = []
    for ind in _ip_or_all(indicators):
        out.append(ind.value)
    return "\n".join(out) + ("\n" if out else "")

# 4.5 Microsoft Sentinel (STIX 2.1 indicators wrapper)
def export_sentinel_stix(indicators: Iterable[Indicator]) -> str:
    objs = []
    now = _utc_iso(datetime.now(timezone.utc))
    for ind in indicators:
        if ind.type == "ip":
            pattern = f"[ipv4-addr:value = '{ind.value}']" if ":" not in ind.value else f"[ipv6-addr:value = '{ind.value}']"
        elif ind.type == "domain":
            pattern = f"[domain-name:value = '{ind.value}']"
        elif ind.type == "url":
            pattern = f"[url:value = '{ind.value}']"
        elif ind.type == "email":
            pattern = f"[email-addr:value = '{ind.value}']"
        else:
            # hash: prefer sha256 if present, otherwise generic
            pattern = f"[file:hashes.'SHA-256' = '{ind.value}']"
        objs.append({
            "pattern": pattern,
            "patternType": "stix",
            "source": "threat-feed-aggregator",
            "validFrom": now,
            "confidence": int(ind.confidence),
            "threatTypes": ["malicious-activity"],
            "tlpLevel": _tlp_lower(ind.tlp),
            "tags": ind.tags or [],
        })
    payload = {"sourcesystem": "ThreatFeedAggregator", "indicators": objs}
    return _json_pretty(payload)

# 4.6 Microsoft Defender for Endpoint (CSV)
_DEFENDER_TYPE_MAP = {
    "ip": "IpAddress",
    "domain": "DomainName",
    "url": "Url",
    "hash": "FileSha256",
}
def export_defender_csv(indicators: Iterable[Indicator]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["IndicatorValue","IndicatorType","Action","Title","Description","Severity","RecommendedActions","Category"])
    for ind in indicators:
        t = _DEFENDER_TYPE_MAP.get(ind.type)
        if not t:
            continue
        sev = _severity_from_confidence(ind.confidence).capitalize()
        w.writerow([
            ind.value,
            t,
            "Block",
            "ThreatFeedAggregator IOC",
            f"Source={ind.source} TLP={ind.tlp} Confidence={ind.confidence}",
            sev,
            "Review and adjust based on internal context",
            "Malware",
        ])
    return buf.getvalue()

# 4.7 F5 BIG-IP (iRule Data Group)
def export_f5_datagroup(indicators: Iterable[Indicator]) -> str:
    out = []
    for ind in _ip_or_all(indicators):
        out.append(f"\"{ind.value}\" := \"malicious,{ind.confidence}\"")
    return "\n".join(out) + ("\n" if out else "")

# 4.8 Imperva WAF (SecureSphere JSON)
def export_imperva_json(indicators: Iterable[Indicator]) -> str:
    entries = []
    for ind in _ip_or_all(indicators):
        entries.append({
            "type": "single",
            "ipAddressFrom": ind.value,
            "ipAddressTo": ind.value,
            "networkMask": "255.255.255.255",
            "comment": "Threat feed indicator",
        })
    payload = {"name": "ThreatFeed-Blocklist", "entries": entries}
    return _json_pretty(payload)

# 4.9 ArcSight (CEF)
def export_arcsight_cef(indicators: Iterable[Indicator]) -> str:
    out = []
    for ind in _ip_or_all(indicators):
        sev = 7 if ind.confidence >= 70 else 5 if ind.confidence >= 50 else 3
        line = (
            f"CEF:0|ThreatFeedAggregator|IOC Feed|1.0|TI-IP|Threat Intelligence: {ind.value}|{sev}| "
            f"src={ind.value} cs1Label=TLP cs1={ind.tlp} cs2Label=Confidence cs2={ind.confidence}"
        )
        out.append(line)
    return "\n".join(out) + ("\n" if out else "")

# 4.10 Elasticsearch (Bulk API NDJSON)
def export_elasticsearch_bulk(indicators: Iterable[Indicator], index_name: str = "threat-intel-indicators") -> str:
    out = []
    now = _utc_iso(datetime.now(timezone.utc))
    for ind in indicators:
        doc_id = f"{ind.source}-{_sanitize_name(ind.value)}"
        out.append(_json_compact({"index": {"_index": index_name, "_id": doc_id}}))
        out.append(_json_compact({
            "@timestamp": now,
            "indicator": {"value": ind.value, "type": ind.type, "confidence": ind.confidence},
            "tlp": ind.tlp,
            "source": ind.source,
            "tags": ind.tags or [],
        }))
    return "\n".join(out) + ("\n" if out else "")

# 4.11 Cribl NDJSON with ECS-ish fields
def export_cribl_ndjson(indicators: Iterable[Indicator]) -> str:
    out = []
    ts = int(time.time())
    for ind in indicators:
        out.append(_json_compact({
            "_time": ts,
            "source": "threat-feed-aggregator",
            "sourcetype": "threat_intelligence",
            "indicator_value": ind.value,
            "indicator_type": ind.type,
            "confidence_score": ind.confidence,
            "threat": {
                "indicator": {
                    "type": ind.type,
                    "confidence": f"{ind.confidence}/100"
                }
            },
            "tlp": ind.tlp,
            "tags": ind.tags or [],
        }))
    return "\n".join(out) + ("\n" if out else "")

# 4.12 Splunk HEC batch
def export_splunk_hec(indicators: Iterable[Indicator], index: str = "threat_intel") -> str:
    ts = int(time.time())
    payload = []
    for ind in indicators:
        payload.append({
            "time": ts,
            "host": "threat-feed-aggregator",
            "source": "threat_intelligence_feed",
            "sourcetype": "threatintel:indicator",
            "index": index,
            "event": {
                "indicator": ind.value,
                "indicator_type": ind.type,
                "confidence": ind.confidence,
                "tlp": ind.tlp,
                "source": ind.source,
                "tags": ind.tags or [],
            }
        })
    return _json_pretty(payload)

# 4.13 Fidelis STIX 2.1 Bundle
def export_fidelis_stix_bundle(indicators: Iterable[Indicator]) -> str:
    now = _utc_iso(datetime.now(timezone.utc))
    bundle_id = f"bundle--threat-feed-{int(time.time())}"
    objects: List[Dict[str, Any]] = []
    for ind in indicators:
        # Deterministic-ish id (not a real UUIDv4, but acceptable for export object identifiers)
        oid = "indicator--" + _sanitize_name(ind.value)
        if ind.type == "ip":
            pattern = f"[ipv4-addr:value = '{ind.value}']" if ":" not in ind.value else f"[ipv6-addr:value = '{ind.value}']"
        elif ind.type == "domain":
            pattern = f"[domain-name:value = '{ind.value}']"
        elif ind.type == "url":
            pattern = f"[url:value = '{ind.value}']"
        elif ind.type == "email":
            pattern = f"[email-addr:value = '{ind.value}']"
        else:
            pattern = f"[file:hashes.'SHA-256' = '{ind.value}']"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": oid,
            "created": now,
            "modified": now,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
            "confidence": ind.confidence,
            "labels": ["malicious-activity"],
            "extensions": {
                "tlp": ind.tlp
            }
        })
    payload = {"type": "bundle", "id": bundle_id, "objects": objects}
    return _json_pretty(payload)

# Registry for routes
FORMATTERS = {
    "txt": (export_txt, "text/plain; charset=utf-8"),
    "csv": (export_csv, "text/csv; charset=utf-8"),
    "json": (export_json, "application/json; charset=utf-8"),
    "xml": (export_xml, "application/xml; charset=utf-8"),

    "fortigate": (export_fortigate_ebl, "text/plain; charset=utf-8"),
    "fortigate_ips": (export_fortigate_ips, "text/plain; charset=utf-8"),
    "checkpoint": (export_checkpoint_csv, "text/csv; charset=utf-8"),
    "paloalto": (export_paloalto_edl, "text/plain; charset=utf-8"),

    "sentinel": (export_sentinel_stix, "application/json; charset=utf-8"),
    "defender": (export_defender_csv, "text/csv; charset=utf-8"),
    "f5": (export_f5_datagroup, "text/plain; charset=utf-8"),
    "imperva": (export_imperva_json, "application/json; charset=utf-8"),

    "arcsight": (export_arcsight_cef, "text/plain; charset=utf-8"),
    "elasticsearch": (export_elasticsearch_bulk, "application/x-ndjson; charset=utf-8"),
    "cribl": (export_cribl_ndjson, "application/x-ndjson; charset=utf-8"),
    "splunk": (export_splunk_hec, "application/json; charset=utf-8"),
    "fidelis": (export_fidelis_stix_bundle, "application/json; charset=utf-8"),
}
