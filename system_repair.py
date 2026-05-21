import winreg

def enable_taskmgr():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False

def enable_power_button():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
                             0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY)
        winreg.SetValueEx(key, "HidePowerButton", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return True  # Ключа нет — значит, не отключено
    except Exception:
        return False

def repair_system():
    results = {}
    results['taskmgr'] = enable_taskmgr()
    results['power_btn'] = enable_power_button()
    return results