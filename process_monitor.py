## process_monitor.py
import psutil
import ctypes
import subprocess
import sys
import os

# === Проверка прав администратора ===

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def run_as_admin():
    if is_admin():
        return False
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            " ".join(f'"{arg}"' for arg in sys.argv),
            None, 1
        )
        return True
    except Exception as e:
        print(f"Ошибка прав: {e}")
        return False


# === Защита процессов ===

_self_pids_cache = None
_self_pids_cache_time = 0


def get_self_pids():
    """PID процессов программы (с кэшированием)"""
    global _self_pids_cache, _self_pids_cache_time
    import time
    
    # Кэш на 5 секунд
    if _self_pids_cache and time.time() - _self_pids_cache_time < 5:
        return _self_pids_cache
    
    protected = set()
    try:
        current = psutil.Process(os.getpid())
        protected.add(current.pid)
        try:
            parent = current.parent()
            if parent:
                protected.add(parent.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    except Exception:
        pass
    
    _self_pids_cache = protected
    _self_pids_cache_time = time.time()
    return protected


PROTECTED_SYSTEM_PROCESSES = {
    'system', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'winlogon.exe', 'lsass.exe', 'services.exe',
    'dwm.exe', 'system idle process', 'registry',
    'secure system', 'memory compression',
}


def is_protected_process(pid):
    if pid in get_self_pids():
        return True, "Процесс программы"
    
    try:
        proc = psutil.Process(pid)
        name = proc.name().lower()
        if name in PROTECTED_SYSTEM_PROCESSES:
            return True, f"Системный: {name}"
        if pid <= 4:
            return True, "Процесс ядра"
    except psutil.NoSuchProcess:
        return False, "Не существует"
    except psutil.AccessDenied:
        pass
    
    return False, ""


# === Методы завершения ===

def _kill_via_psutil(pid):
    try:
        proc = psutil.Process(pid)
        proc.kill()
        proc.wait(timeout=3)
        return True, "psutil"
    except psutil.TimeoutExpired:
        return False, "psutil: таймаут"
    except psutil.NoSuchProcess:
        return True, "Уже завершён"
    except psutil.AccessDenied:
        return False, "psutil: отказано в доступе"
    except Exception as e:
        return False, f"psutil: {e}"


def _kill_via_winapi(pid):
    PROCESS_TERMINATE = 0x0001
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if not handle:
            err = ctypes.get_last_error()
            if err == 87:
                return True, "Уже завершён"
            return False, f"WinAPI: код {err}"
        try:
            result = kernel32.TerminateProcess(handle, 1)
            if result:
                return True, "WinAPI"
            return False, f"WinAPI: код {ctypes.get_last_error()}"
        finally:
            kernel32.CloseHandle(handle)
    except Exception as e:
        return False, f"WinAPI: {e}"


def _kill_via_taskkill(pid):
    try:
        result = subprocess.run(
            ["taskkill", "/F", "/PID", str(pid), "/T"],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if result.returncode == 0:
            return True, "taskkill"
        if result.returncode == 128:
            return True, "Уже завершён"
        return False, f"taskkill: {result.stderr.strip()}"
    except Exception as e:
        return False, f"taskkill: {e}"


def kill_process(pid, kill_children=True):
    protected, reason = is_protected_process(pid)
    if protected:
        return False, f"Защищён: {reason}"
    
    if kill_children:
        self_pids = get_self_pids()
        try:
            parent = psutil.Process(pid)
            for child in parent.children(recursive=True):
                if child.pid in self_pids:
                    continue
                try:
                    child.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    last_msg = ""
    for method in [_kill_via_psutil, _kill_via_winapi, _kill_via_taskkill]:
        success, msg = method(pid)
        if success:
            return True, f"Процесс {pid} завершён ({msg})"
        last_msg = msg
    
    return False, f"Не удалось завершить {pid}. {last_msg}"


# ==========================================
# CPU МОНИТОРИНГ
# ==========================================

_cpu_cache = {}


def _init_cpu_measurement():
    """Инициализация измерения CPU при запуске модуля"""
    for proc in psutil.process_iter(['pid']):
        try:
            proc.cpu_percent(interval=None)
            _cpu_cache[proc.pid] = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


_init_cpu_measurement()


# Кэш для служб svchost
_services_cache = {}
_services_cache_time = 0


def _get_services_for_pid(pid):
    """Получает службы для PID с кэшированием"""
    global _services_cache, _services_cache_time
    import time
    
    # Обновляем кэш каждые 30 секунд
    if time.time() - _services_cache_time > 30:
        _services_cache = {}
        try:
            for svc in psutil.win_service_iter():
                try:
                    svc_pid = svc.pid()
                    if svc_pid:
                        if svc_pid not in _services_cache:
                            _services_cache[svc_pid] = []
                        _services_cache[svc_pid].append(svc.name())
                except Exception:
                    continue
        except Exception:
            pass
        _services_cache_time = time.time()
    
    return _services_cache.get(pid, [])


def get_aggregated_process_list():
    """Возвращает список процессов с корректным CPU %"""
    global _cpu_cache
    
    processes = {}
    self_pids = get_self_pids()
    cpu_count = psutil.cpu_count(logical=True) or 1

    current_pids = set()
    raw_processes = []
    
    # Собираем CPU метрики для всех процессов
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid = proc.info['pid']
            current_pids.add(pid)
            
            if pid not in _cpu_cache:
                proc.cpu_percent(interval=None)
                _cpu_cache[pid] = True
                cpu_raw = 0.0
            else:
                cpu_raw = proc.cpu_percent(interval=None)
            
            raw_processes.append((proc, cpu_raw))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    # Очистка кэша от завершённых процессов
    for pid in list(_cpu_cache.keys()):
        if pid not in current_pids:
            del _cpu_cache[pid]
    
    # Формируем результат
    for proc, cpu_raw in raw_processes:
        try:
            info = proc.as_dict(attrs=[
                'pid', 'name', 'username', 
                'memory_info', 'num_threads', 'exe'
            ])
            
            if not info['name']:
                continue
            
            name_lower = info['name'].lower()
            
            # System Idle Process - пропускаем
            if name_lower == 'system idle process':
                continue
            
            # Нормализуем CPU
            cpu_normalized = min(cpu_raw / cpu_count, 100.0)
            
            mem_mb = 0
            if info['memory_info']:
                mem_mb = info['memory_info'].rss / (1024 * 1024)
            
            threads = info['num_threads'] or 0
            is_self = info['pid'] in self_pids
            exe_path = info.get('exe') or ''

            # Агрегация svchost
            if name_lower == 'svchost.exe':
                key = f"svchost ({threads} threads)"
            else:
                key = info['name']

            if key in processes:
                processes[key]['cpu'] += cpu_normalized
                processes[key]['mem'] += mem_mb
                processes[key]['threads'] += threads
                processes[key]['all_pids'].append(info['pid'])
            else:
                services = []
                if key.startswith("svchost"):
                    services = _get_services_for_pid(info['pid'])
                
                processes[key] = {
                    'pid': info['pid'],
                    'all_pids': [info['pid']],
                    'name': key,
                    'user': info['username'] or '',
                    'cpu': cpu_normalized,
                    'mem': mem_mb,
                    'threads': threads,
                    'services': services,
                    'is_self': is_self,
                    'exe_path': exe_path,
                }

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue
    
    # Ограничение CPU
    for proc in processes.values():
        proc['cpu'] = min(proc['cpu'], 100.0)

    return list(processes.values())


_SUSPICIOUS_KEYWORDS = ('miner', 'stealer', 'crypt', 'trojan', 'malware', 'keylog', 'rat')


def is_suspicious_process(name):
    if not name:
        return False
    name_lower = name.lower()
    return any(k in name_lower for k in _SUSPICIOUS_KEYWORDS)