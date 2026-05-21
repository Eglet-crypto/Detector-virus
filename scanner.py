# scanner.py
import os
import hashlib
import shutil
import time

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

SIGNATURES_FILE = "signatures.txt"
YARA_RULES_DIR = "Yara_rules"
QUARANTINE_DIR = "quarantine"

# Кэш сигнатур
_signatures_cache = None
_signatures_cache_time = 0
_SIGNATURES_CACHE_TTL = 60  # секунд


def get_file_hash(filepath, algorithm="sha256", chunk_size=65536):
    """Вычисляет хэш файла (оптимизированный chunk_size)"""
    h = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError):
        return None


def get_both_hashes(filepath, chunk_size=65536):
    """Вычисляет MD5 и SHA256 за один проход файла"""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()
    except (PermissionError, OSError):
        return None, None


def load_signatures(force_reload=False):
    """Загружает сигнатуры из signatures.txt с кэшированием"""
    global _signatures_cache, _signatures_cache_time
    
    if not force_reload and _signatures_cache is not None:
        if time.time() - _signatures_cache_time < _SIGNATURES_CACHE_TTL:
            return _signatures_cache
    
    result = {}
    if not os.path.exists(SIGNATURES_FILE):
        _signatures_cache = result
        _signatures_cache_time = time.time()
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
                if hash_val:
                    result[hash_val] = name
    except Exception as e:
        print(f"Ошибка загрузки сигнатур: {e}")
    
    _signatures_cache = result
    _signatures_cache_time = time.time()
    return result


def invalidate_signatures_cache():
    """Сбрасывает кэш сигнатур"""
    global _signatures_cache, _signatures_cache_time
    _signatures_cache = None
    _signatures_cache_time = 0


def compile_yara_rules():
    rules = []
    if not HAS_YARA:
        return rules
    if not os.path.exists(YARA_RULES_DIR):
        os.makedirs(YARA_RULES_DIR, exist_ok=True)
        return rules

    for filename in os.listdir(YARA_RULES_DIR):
        if filename.endswith((".yar", ".yara")):
            try:
                path = os.path.join(YARA_RULES_DIR, filename)
                rules.append(yara.compile(filepath=path))
            except Exception as e:
                print(f"YARA {filename}: {e}")
    return rules


def delete_file(filepath):
    try:
        os.remove(filepath)
        return True
    except Exception:
        return False


def move_to_quarantine(filepath):
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        filename = os.path.basename(filepath)
        import datetime
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = os.path.join(QUARANTINE_DIR, f"{ts}_{filename}.quarantine")
        shutil.move(filepath, dest)
        return dest
    except Exception:
        return None