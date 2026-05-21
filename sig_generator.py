# sig_generator.py
import os
import sys
import hashlib
import datetime
import shutil

SIGNATURES_FILE = "signatures.txt"
BACKUP_DIR = "sig_backups"


def compute_hashes(filepath):
    if not os.path.isfile(filepath):
        return None
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                md5.update(chunk)
                sha256.update(chunk)
        return {
            "md5": md5.hexdigest(),
            "sha256": sha256.hexdigest(),
            "size": os.path.getsize(filepath),
            "filename": os.path.basename(filepath),
        }
    except (PermissionError, OSError):
        return None


def load_signatures_dict():
    result = {}
    if not os.path.exists(SIGNATURES_FILE):
        return result
    try:
        with open(SIGNATURES_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":", 3)
                if len(parts) < 2:
                    continue
                hash_val = parts[0].strip().lower()
                name = parts[1].strip()
                ttype = parts[2].strip() if len(parts) > 2 else "malware"
                desc = parts[3].strip() if len(parts) > 3 else ""
                if hash_val:
                    result[hash_val] = {
                        "name": name,
                        "type": ttype,
                        "description": desc,
                    }
    except Exception as e:
        print(f"Ошибка: {e}")
    return result


def save_signatures_dict(sigs_dict):
    # Бэкап
    if os.path.exists(SIGNATURES_FILE):
        try:
            os.makedirs(BACKUP_DIR, exist_ok=True)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = os.path.join(BACKUP_DIR, f"signatures_{ts}.txt")
            shutil.copy2(SIGNATURES_FILE, backup_path)
            backups = sorted(os.listdir(BACKUP_DIR))
            while len(backups) > 10:
                os.remove(os.path.join(BACKUP_DIR, backups.pop(0)))
        except Exception:
            pass

    try:
        with open(SIGNATURES_FILE, "w", encoding="utf-8") as f:
            f.write(f"# Антивирус - база сигнатур\n")
            f.write(f"# Обновлено: {datetime.datetime.now().isoformat()}\n")
            f.write(f"# Всего: {len(sigs_dict)}\n\n")
            for hash_val, entry in sorted(sigs_dict.items()):
                name = entry.get("name", "Unknown")
                ttype = entry.get("type", "malware")
                desc = entry.get("description", "").replace(":", ";")
                f.write(f"{hash_val}:{name}:{ttype}:{desc}\n")
        
        # Сбрасываем кэш сканера
        try:
            from scanner import invalidate_signatures_cache
            invalidate_signatures_cache()
        except ImportError:
            pass
        return True
    except Exception as e:
        print(f"Ошибка: {e}")
        return False


def add_signature(filepath, threat_name, threat_type="malware", description=""):
    hashes = compute_hashes(filepath)
    if not hashes:
        return False, f"Не удалось вычислить хэш: {filepath}"

    sigs = load_signatures_dict()
    sha = hashes["sha256"]
    md5 = hashes["md5"]

    if sha in sigs:
        return False, f"Уже существует: {sigs[sha].get('name')}"

    sigs[sha] = {
        "name": threat_name, "type": threat_type,
        "description": description or f"Файл: {hashes['filename']}",
    }
    sigs[md5] = {
        "name": threat_name, "type": threat_type,
        "description": description or f"Файл: {hashes['filename']} (MD5)",
    }

    if save_signatures_dict(sigs):
        return True, (
            f"✅ Добавлено!\nФайл: {hashes['filename']}\n"
            f"SHA256: {sha}\nMD5: {md5}"
        )
    return False, "Ошибка сохранения"


def add_hash_manually(hash_value, threat_name, threat_type="malware", description=""):
    hash_value = hash_value.strip().lower()
    if len(hash_value) not in (32, 64):
        return False, f"Некорректный хэш (длина {len(hash_value)})"

    sigs = load_signatures_dict()
    if hash_value in sigs:
        return False, f"Уже существует: {sigs[hash_value].get('name')}"

    sigs[hash_value] = {
        "name": threat_name, "type": threat_type,
        "description": description,
    }
    if save_signatures_dict(sigs):
        return True, f"✅ '{threat_name}' добавлено"
    return False, "Ошибка"


def import_from_csv(csv_path):
    added = skipped = errors = 0
    sigs = load_signatures_dict()
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 2:
                    errors += 1
                    continue
                hash_val = parts[0].lower()
                name = parts[1]
                ttype = parts[2] if len(parts) > 2 else "malware"
                desc = parts[3] if len(parts) > 3 else ""
                if len(hash_val) not in (32, 64):
                    errors += 1
                    continue
                if hash_val in sigs:
                    skipped += 1
                    continue
                sigs[hash_val] = {"name": name, "type": ttype, "description": desc}
                added += 1
        if added > 0:
            save_signatures_dict(sigs)
    except Exception as e:
        print(f"Ошибка импорта: {e}")
        errors += 1
    return added, skipped, errors


def export_to_csv(csv_path):
    sigs = load_signatures_dict()
    try:
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write("# hash,threat_name,threat_type,description\n")
            for hash_val, entry in sigs.items():
                name = entry.get("name", "unknown")
                ttype = entry.get("type", "malware")
                desc = entry.get("description", "").replace(",", ";")
                f.write(f"{hash_val},{name},{ttype},{desc}\n")
        return True, len(sigs)
    except Exception:
        return False, 0


def get_stats():
    sigs = load_signatures_dict()
    types = {}
    for entry in sigs.values():
        t = entry.get("type", "unknown")
        types[t] = types.get(t, 0) + 1
    last_modified = ""
    if os.path.exists(SIGNATURES_FILE):
        ts = os.path.getmtime(SIGNATURES_FILE)
        last_modified = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
    return {
        "total": len(sigs),
        "updated": last_modified,
        "by_type": types,
    }