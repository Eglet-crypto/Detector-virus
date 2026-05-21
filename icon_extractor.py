# icon_extractor.py
import os
from collections import OrderedDict
from PyQt5.QtGui import QIcon, QPixmap, QPainter, QColor, QFont
from PyQt5.QtCore import QSize, Qt, QFileInfo
from PyQt5.QtWidgets import QFileIconProvider

# LRU кэш (ограничен размером для экономии памяти)
_MAX_CACHE_SIZE = 500
_icon_cache = OrderedDict()
_file_icon_provider = QFileIconProvider()


def _add_to_cache(key, icon):
    """Добавляет иконку в LRU кэш"""
    if key in _icon_cache:
        _icon_cache.move_to_end(key)
    else:
        _icon_cache[key] = icon
        if len(_icon_cache) > _MAX_CACHE_SIZE:
            _icon_cache.popitem(last=False)


def get_process_icon(exe_path, name="", size=20):
    """Извлекает иконку процесса"""
    cache_key = f"{exe_path}_{name}_{size}"
    
    if cache_key in _icon_cache:
        _icon_cache.move_to_end(cache_key)
        return _icon_cache[cache_key]

    icon = None

    # Метод 1: из exe
    if exe_path and os.path.isfile(exe_path):
        try:
            file_info = QFileInfo(exe_path)
            icon_qt = _file_icon_provider.icon(file_info)
            if icon_qt and not icon_qt.isNull():
                pixmap = icon_qt.pixmap(QSize(size, size))
                if not pixmap.isNull() and pixmap.width() > 0:
                    _add_to_cache(cache_key, icon_qt)
                    return icon_qt
        except Exception:
            pass

    # Метод 2: системный - шестерёнка
    if _is_system_process(name):
        icon = _create_gear_icon(size)
        _add_to_cache(cache_key, icon)
        return icon

    # Метод 3: по умолчанию
    icon = _create_default_icon(size, name)
    _add_to_cache(cache_key, icon)
    return icon


_SYSTEM_PROCESSES = frozenset({
    'system', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'winlogon.exe', 'lsass.exe', 'services.exe',
    'svchost.exe', 'dwm.exe', 'conhost.exe',
    'fontdrvhost.exe', 'lsaiso.exe', 'memory compression',
    'registry', 'secure system', 'system idle process',
    'dashost.exe', 'spoolsv.exe', 'wuauserv',
    'searchindexer.exe', 'searchhost.exe', 'searchapp.exe',
    'securityhealthservice.exe', 'sgrmbroker.exe',
    'sihost.exe', 'smartscreen.exe', 'audiodg.exe',
    'ctfmon.exe', 'dllhost.exe', 'msdtc.exe',
    'taskhostw.exe', 'runtimebroker.exe',
    'wsappx', 'wlanext.exe', 'wmiprvse.exe',
    'compptmgr.exe', 'ntoskrnl.exe', 'idle',
    'shellexperiencehost.exe', 'startmenuexperiencehost.exe',
    'applicationframehost.exe', 'systemsettings.exe',
})


def _is_system_process(name):
    if not name:
        return False
    clean = name.lower().strip()
    if clean in _SYSTEM_PROCESSES:
        return True
    if clean.startswith("svchost"):
        return True
    return False


def _create_gear_icon(size=20):
    cache_key = f"_gear_{size}"
    if cache_key in _icon_cache:
        return _icon_cache[cache_key]

    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)

    center = size // 2
    
    # Зубцы
    painter.setBrush(QColor(90, 90, 90))
    painter.setPen(Qt.NoPen)
    tooth = max(size // 5, 3)
    
    positions = [
        (center - tooth // 2, 0),
        (center - tooth // 2, size - tooth),
        (0, center - tooth // 2),
        (size - tooth, center - tooth // 2),
        (1, 1),
        (size - tooth - 1, 1),
        (1, size - tooth - 1),
        (size - tooth - 1, size - tooth - 1),
    ]
    for x, y in positions:
        painter.drawRect(x, y, tooth, tooth)

    # Главный круг
    painter.setBrush(QColor(120, 120, 120))
    margin = max(size // 8, 2)
    painter.drawEllipse(margin, margin, size - 2 * margin, size - 2 * margin)

    # Отверстие
    painter.setBrush(QColor(50, 50, 50))
    inner_r = max(size // 5, 2)
    painter.drawEllipse(
        center - inner_r, center - inner_r,
        inner_r * 2, inner_r * 2
    )

    painter.end()
    icon = QIcon(pixmap)
    _icon_cache[cache_key] = icon
    return icon


def _create_default_icon(size=20, name=""):
    first = name[0].upper() if name else "?"
    cache_key = f"_default_{first}_{size}"
    
    if cache_key in _icon_cache:
        return _icon_cache[cache_key]

    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing, True)

    hue = (ord(first) * 37) % 360
    bg = QColor.fromHsv(hue, 120, 200)

    painter.setBrush(bg)
    painter.setPen(Qt.NoPen)
    painter.drawEllipse(1, 1, size - 2, size - 2)

    painter.setPen(QColor(255, 255, 255))
    font = QFont("Arial", max(size // 3, 6), QFont.Bold)
    painter.setFont(font)
    painter.drawText(0, 0, size, size, Qt.AlignCenter, first)

    painter.end()
    icon = QIcon(pixmap)
    _icon_cache[cache_key] = icon
    return icon


def clear_icon_cache():
    _icon_cache.clear()