# threat_feeds.py
import os
import json
import time

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

API_KEYS_FILE = "api_keys.json"
DEFAULT_TIMEOUT = 30
MIN_DETECTIONS_VT = 3
HEADERS = {"User-Agent": "Antivirus/1.0"}


def load_api_keys():
    if not os.path.exists(API_KEYS_FILE):
        template = {
            "abusech": "",
            "virustotal": "",
            "malshare": "",
            "_comment_abusech": "Получите БЕСПЛАТНО на https://auth.abuse.ch/",
        }
        try:
            with open(API_KEYS_FILE, "w", encoding="utf-8") as f:
                json.dump(template, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
        return template
    try:
        with open(API_KEYS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_api_keys(keys):
    try:
        with open(API_KEYS_FILE, "w", encoding="utf-8") as f:
            json.dump(keys, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def _get_abusech_key():
    return load_api_keys().get("abusech", "").strip()


def fetch_malwarebazaar_recent(limit=100, log_callback=None):
    if not HAS_REQUESTS:
        return []
    auth_key = _get_abusech_key()
    if not auth_key:
        if log_callback:
            log_callback("❌ MalwareBazaar: нет Auth-Key")
        return []
    if log_callback:
        log_callback(f"🌐 MalwareBazaar: загрузка {limit} образцов...")

    selector = "10" if limit <= 10 else "50" if limit <= 50 else "100"
    
    try:
        response = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_recent", "selector": selector},
            headers={**HEADERS, "Auth-Key": auth_key},
            timeout=DEFAULT_TIMEOUT
        )
    except Exception as e:
        if log_callback:
            log_callback(f"❌ MalwareBazaar: {e}")
        return []
    
    if response.status_code != 200:
        if log_callback:
            log_callback(f"❌ HTTP {response.status_code}")
        return []
    
    try:
        result = response.json()
    except Exception:
        return []
    
    if result.get("query_status") != "ok":
        if log_callback:
            log_callback(f"❌ {result.get('query_status')}")
        return []
    
    signatures = []
    items = result.get("data", [])
    
    for item in items:
        sha256 = (item.get("sha256_hash") or "").lower()
        md5 = (item.get("md5_hash") or "").lower()
        signature = item.get("signature") or item.get("file_type") or "Unknown"
        file_type = item.get("file_type", "")
        tags = item.get("tags") or []
        
        threat_type = _detect_threat_type(tags)
        description = f"MalwareBazaar | {file_type}"
        if tags:
            description += f" | {','.join(tags[:5])}"
        
        if sha256:
            signatures.append({
                "hash": sha256, "name": f"MB.{signature}",
                "type": threat_type, "description": description,
                "source": "MalwareBazaar",
            })
        if md5:
            signatures.append({
                "hash": md5, "name": f"MB.{signature}",
                "type": threat_type, "description": description + " (MD5)",
                "source": "MalwareBazaar",
            })
    
    if log_callback:
        log_callback(f"✅ MalwareBazaar: {len(signatures)} сигнатур")
    return signatures


def fetch_malwarebazaar_by_tag(tag, limit=50, log_callback=None):
    if not HAS_REQUESTS:
        return []
    auth_key = _get_abusech_key()
    if not auth_key:
        return []
    if log_callback:
        log_callback(f"🌐 Тег '{tag}'...")

    try:
        response = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_taginfo", "tag": tag, "limit": str(min(limit, 1000))},
            headers={**HEADERS, "Auth-Key": auth_key},
            timeout=DEFAULT_TIMEOUT
        )
    except Exception as e:
        if log_callback:
            log_callback(f"❌ Тег '{tag}': {e}")
        return []
    
    if response.status_code != 200:
        return []
    
    try:
        result = response.json()
    except Exception:
        return []
    
    status = result.get("query_status", "unknown")
    if status in ("no_results", "tag_not_found"):
        if log_callback:
            log_callback(f"⚠️ Тег '{tag}': нет данных")
        return []
    if status != "ok":
        return []
    
    signatures = []
    for item in result.get("data", []):
        sha256 = (item.get("sha256_hash") or "").lower()
        signature = item.get("signature") or tag
        if sha256:
            signatures.append({
                "hash": sha256, "name": f"MB.{signature}",
                "type": _tag_to_type(tag),
                "description": f"MalwareBazaar tag: {tag}",
                "source": "MalwareBazaar",
            })
    
    if log_callback:
        log_callback(f"✅ Тег '{tag}': {len(signatures)}")
    return signatures


def _detect_threat_type(tags):
    if not tags:
        return "malware"
    tags_lower = [t.lower() for t in tags]
    if any(t in tags_lower for t in ["ransomware", "ransom"]):
        return "ransomware"
    if any(t in tags_lower for t in ["miner", "coinminer", "xmrig"]):
        return "miner"
    if any(t in tags_lower for t in ["spyware", "stealer", "infostealer"]):
        return "spyware"
    if "worm" in tags_lower:
        return "worm"
    if "rootkit" in tags_lower:
        return "rootkit"
    if "adware" in tags_lower:
        return "adware"
    if any(t in tags_lower for t in ["trojan", "rat", "backdoor"]):
        return "trojan"
    return "malware"


def _tag_to_type(tag):
    return _detect_threat_type([tag])


def fetch_threatfox_recent(days=3, log_callback=None):
    if not HAS_REQUESTS:
        return []
    auth_key = _get_abusech_key()
    if not auth_key:
        if log_callback:
            log_callback("❌ ThreatFox: нет Auth-Key")
        return []
    if log_callback:
        log_callback(f"🌐 ThreatFox: за {days} дн...")

    try:
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": min(max(days, 1), 7)},
            headers={**HEADERS, "Auth-Key": auth_key, "Content-Type": "application/json"},
            timeout=DEFAULT_TIMEOUT
        )
    except Exception as e:
        if log_callback:
            log_callback(f"❌ ThreatFox: {e}")
        return []
    
    if response.status_code != 200:
        return []
    
    try:
        result = response.json()
    except Exception:
        return []
    
    if result.get("query_status") != "ok":
        return []
    
    signatures = []
    items = result.get("data", [])
    
    for item in items:
        ioc_type = item.get("ioc_type", "")
        ioc_value = (item.get("ioc") or "").lower()
        malware = item.get("malware_printable", "Unknown")
        threat_type_raw = item.get("threat_type", "malware")
        
        if ioc_type not in ("md5_hash", "sha256_hash", "sha1_hash"):
            continue
        
        tt = threat_type_raw.lower()
        if "ransomware" in tt:
            threat_type = "ransomware"
        elif "miner" in tt:
            threat_type = "miner"
        elif "trojan" in tt or "rat" in tt:
            threat_type = "trojan"
        else:
            threat_type = "malware"
        
        signatures.append({
            "hash": ioc_value, "name": f"TF.{malware}",
            "type": threat_type,
            "description": f"ThreatFox | {ioc_type}",
            "source": "ThreatFox",
        })
    
    if log_callback:
        log_callback(f"✅ ThreatFox: {len(signatures)} хэшей")
    return signatures


def check_hash_virustotal(hash_value, api_key=None, log_callback=None):
    if not HAS_REQUESTS:
        return None
    if not api_key:
        api_key = load_api_keys().get("virustotal", "")
    if not api_key:
        if log_callback:
            log_callback("❌ VT: нет ключа")
        return None

    hash_value = hash_value.strip().lower()
    
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{hash_value}",
            headers={"x-apikey": api_key},
            timeout=DEFAULT_TIMEOUT
        )
    except Exception as e:
        if log_callback:
            log_callback(f"❌ VT: {e}")
        return None
    
    if response.status_code == 404:
        if log_callback:
            log_callback(f"❓ VT: неизвестен")
        return None
    if response.status_code != 200:
        if log_callback:
            log_callback(f"❌ VT: HTTP {response.status_code}")
        return None
    
    try:
        data = response.json()
    except Exception:
        return None
    
    attributes = data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())
    
    if malicious < MIN_DETECTIONS_VT:
        if log_callback:
            log_callback(f"✅ VT: чистый ({malicious}/{total})")
        return None
    
    results = attributes.get("last_analysis_results", {})
    threat_name = "Unknown.Malware"
    threat_type = "malware"
    
    for av in ["Microsoft", "Kaspersky", "ESET-NOD32", "BitDefender"]:
        if av in results:
            detection = results[av].get("result")
            if detection:
                threat_name = detection
                nl = detection.lower()
                if "trojan" in nl:
                    threat_type = "trojan"
                elif "ransom" in nl:
                    threat_type = "ransomware"
                elif "miner" in nl:
                    threat_type = "miner"
                break
    
    return {
        "hash": hash_value, "name": f"VT.{threat_name}",
        "type": threat_type,
        "description": f"VirusTotal | {malicious}/{total}",
        "source": "VirusTotal",
        "detections": malicious, "total_engines": total,
    }


def test_abusech_connection(log_callback=None):
    if not HAS_REQUESTS:
        return False, "Нет requests"
    auth_key = _get_abusech_key()
    if not auth_key:
        return False, "Нет Auth-Key"
    
    try:
        response = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_recent", "selector": "10"},
            headers={**HEADERS, "Auth-Key": auth_key},
            timeout=15
        )
    except Exception as e:
        return False, str(e)
    
    if response.status_code != 200:
        return False, f"HTTP {response.status_code}"
    
    try:
        result = response.json()
    except Exception:
        return False, "Невалидный JSON"
    
    status = result.get("query_status", "unknown")
    if status == "ok":
        return True, f"OK ({len(result.get('data', []))} образцов)"
    elif status == "unauthenticated":
        return False, "Неверный Auth-Key"
    return False, f"Статус: {status}"


def update_all_feeds(
    use_malwarebazaar=True, use_threatfox=True,
    use_virustotal=False, use_malshare=False,
    malwarebazaar_limit=100, threatfox_days=3,
    tags=None, log_callback=None
):
    if not HAS_REQUESTS:
        return []
    
    all_signatures = []
    
    if log_callback:
        log_callback("=" * 50)
        log_callback("🌐 Обновление базы")
        log_callback("=" * 50)
    
    if (use_malwarebazaar or use_threatfox) and not _get_abusech_key():
        if log_callback:
            log_callback("⚠️ Нет Auth-Key: https://auth.abuse.ch/")
    
    if use_malwarebazaar:
        all_signatures.extend(fetch_malwarebazaar_recent(malwarebazaar_limit, log_callback))
        time.sleep(1)
    
    if use_malwarebazaar and tags:
        for tag in tags:
            all_signatures.extend(fetch_malwarebazaar_by_tag(tag, 50, log_callback))
            time.sleep(1)
    
    if use_threatfox:
        all_signatures.extend(fetch_threatfox_recent(threatfox_days, log_callback))
    
    unique = {}
    for sig in all_signatures:
        h = sig["hash"]
        if h and h not in unique:
            unique[h] = sig
    
    if log_callback:
        log_callback("=" * 50)
        log_callback(f"📊 Уникальных: {len(unique)}")
        log_callback("=" * 50)
    return list(unique.values())


def merge_signatures_to_db(new_signatures, log_callback=None):
    try:
        from sig_generator import load_signatures_dict, save_signatures_dict
    except ImportError:
        return 0, 0
    
    existing = load_signatures_dict()
    added = skipped = 0
    
    for sig in new_signatures:
        h = sig["hash"]
        if not h:
            continue
        if h in existing:
            skipped += 1
            continue
        existing[h] = {
            "name": sig["name"], "type": sig["type"],
            "description": sig.get("description", ""),
        }
        added += 1
    
    if save_signatures_dict(existing):
        if log_callback:
            log_callback(f"✅ +{added}, дублей: {skipped}")
        return added, skipped
    return 0, 0