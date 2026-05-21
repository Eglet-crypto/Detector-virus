# -*- coding: utf-8 -*-
# main.py - Антивирус

import os
import sys
import time
import json
import datetime
from collections import deque

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTableWidget, QTableWidgetItem, QPushButton,
    QTextEdit, QFileDialog, QMessageBox, QProgressBar, QLineEdit,
    QDesktopWidget, QLabel, QHeaderView, QAbstractItemView,
    QComboBox, QGroupBox, QFormLayout, QCheckBox, QSpinBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer
from PyQt5.QtGui import QColor, QIcon

from scanner import (
    load_signatures, get_file_hash, get_both_hashes, compile_yara_rules,
    delete_file, move_to_quarantine
)
from process_monitor import (
    get_aggregated_process_list, kill_process, is_suspicious_process,
    is_admin, run_as_admin
)
from icon_extractor import get_process_icon, clear_icon_cache
from sig_generator import (
    add_signature, add_hash_manually, get_stats,
    compute_hashes, export_to_csv, import_from_csv
)

try:
    from threat_feeds import (
        update_all_feeds, merge_signatures_to_db,
        check_hash_virustotal, load_api_keys, save_api_keys,
        test_abusech_connection
    )
    HAS_THREAT_FEEDS = True
except ImportError:
    HAS_THREAT_FEEDS = False


APP_NAME = "Антивирус"
APP_VERSION = "1.0"

# === Автообновление ===
AUTO_UPDATE_CONFIG_FILE = "auto_update_config.json"

DEFAULT_AUTO_UPDATE = {
    "enabled": True,
    "interval_hours": 6,
    "on_startup": True,
    "min_hours_since_last": 12,
    "last_update": "",
    "sources": {
        "malwarebazaar": True,
        "malwarebazaar_limit": 100,
        "threatfox": True,
        "threatfox_days": 3,
        "tags": ["RedLineStealer", "AgentTesla", "Emotet", "Qakbot"],
    }
}

MAX_LOG_LINES = 1000  # Ограничение лога


def load_auto_update_config():
    if not os.path.exists(AUTO_UPDATE_CONFIG_FILE):
        save_auto_update_config(DEFAULT_AUTO_UPDATE)
        return DEFAULT_AUTO_UPDATE.copy()
    try:
        with open(AUTO_UPDATE_CONFIG_FILE, "r", encoding="utf-8") as f:
            config = json.load(f)
        for key, value in DEFAULT_AUTO_UPDATE.items():
            if key not in config:
                config[key] = value
        return config
    except Exception:
        return DEFAULT_AUTO_UPDATE.copy()


def save_auto_update_config(config):
    try:
        with open(AUTO_UPDATE_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def hours_since_last_update(config):
    last = config.get("last_update", "")
    if not last:
        return float('inf')
    try:
        last_dt = datetime.datetime.fromisoformat(last)
        delta = datetime.datetime.now() - last_dt
        return delta.total_seconds() / 3600
    except Exception:
        return float('inf')


# ==========================================
# ПОТОКИ
# ==========================================

class ProcessUpdateThread(QThread):
    updated = pyqtSignal(list)

    def __init__(self, interval=2):
        super().__init__()
        self.interval = interval
        self.running = True

    def run(self):
        while self.running:
            try:
                processes = get_aggregated_process_list()
                self.updated.emit(processes)
            except Exception as e:
                print(f"Процессы: {e}")
            # Прерываемый sleep
            for _ in range(self.interval * 10):
                if not self.running:
                    return
                self.msleep(100)

    def stop(self):
        self.running = False
        self.wait(2000)


class ScannerThread(QThread):
    update_log = pyqtSignal(str)
    progress_update = pyqtSignal(int)
    finished = pyqtSignal(list)

    def __init__(self, folder):
        super().__init__()
        self.folder = folder
        self.running = True

    def stop(self):
        self.running = False

    def run(self):
        try:
            self.update_log.emit(f"🔍 Сканирование: {self.folder}")
            sigs = load_signatures()
            self.update_log.emit(f"📋 Сигнатур: {len(sigs)}")

            # Подсчёт файлов
            total = 0
            for _, _, files in os.walk(self.folder):
                total += len(files)
            
            if total == 0:
                self.update_log.emit("⚠️ Папка пуста")
                self.finished.emit([])
                return

            processed = 0
            all_threats = []
            last_progress = 0

            # === Этап 1: сигнатуры (с одним проходом файла для MD5+SHA256) ===
            self.update_log.emit("📋 Этап 1/2: Сигнатуры...")
            for root, dirs, files in os.walk(self.folder):
                if not self.running:
                    return
                
                for file in files:
                    if not self.running:
                        return
                    path = os.path.join(root, file)
                    try:
                        # Получаем оба хэша за один проход
                        md5, sha256 = get_both_hashes(path)
                        
                        if sha256 and sha256 in sigs:
                            all_threats.append({
                                "path": path, "name": file,
                                "threat": sigs[sha256], "method": "signature"
                            })
                            self.update_log.emit(f"  🚨 {file}: {sigs[sha256]}")
                        elif md5 and md5 in sigs:
                            all_threats.append({
                                "path": path, "name": file,
                                "threat": sigs[md5], "method": "signature"
                            })
                            self.update_log.emit(f"  🚨 {file}: {sigs[md5]}")
                    except (PermissionError, OSError):
                        pass
                    
                    processed += 1
                    progress = int(processed / total * 50)
                    if progress > last_progress:
                        self.progress_update.emit(progress)
                        last_progress = progress

            # === Этап 2: YARA ===
            self.update_log.emit("📋 Этап 2/2: YARA...")
            try:
                yara_rules = compile_yara_rules()
                self.update_log.emit(f"📋 YARA правил: {len(yara_rules)}")
            except Exception as e:
                self.update_log.emit(f"⚠️ YARA: {e}")
                yara_rules = []

            if yara_rules:
                processed = 0
                last_progress = 50
                for root, dirs, files in os.walk(self.folder):
                    if not self.running:
                        return
                    for file in files:
                        if not self.running:
                            return
                        path = os.path.join(root, file)
                        try:
                            if os.path.getsize(path) > 50 * 1024 * 1024:
                                continue
                            with open(path, "rb") as f:
                                data = f.read()
                            for rule in yara_rules:
                                matches = rule.match(data=data)
                                if matches:
                                    threat = ", ".join([m.rule for m in matches])
                                    all_threats.append({
                                        "path": path, "name": file,
                                        "threat": threat, "method": "yara"
                                    })
                                    self.update_log.emit(f"  🚨 YARA: {file} → {threat}")
                        except (PermissionError, OSError):
                            pass
                        processed += 1
                        progress = 50 + int(processed / total * 50)
                        if progress > last_progress:
                            self.progress_update.emit(progress)
                            last_progress = progress

            self.progress_update.emit(100)
            self.update_log.emit(f"\n✅ Завершено. Угроз: {len(all_threats)}")
            self.finished.emit(all_threats)

        except Exception as e:
            self.update_log.emit(f"❌ Ошибка: {e}")
            self.finished.emit([])


class FeedsUpdateThread(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(int, int)

    def __init__(self, use_mb=True, use_tf=True, mb_limit=100, tf_days=3, tags=None):
        super().__init__()
        self.use_mb = use_mb
        self.use_tf = use_tf
        self.mb_limit = mb_limit
        self.tf_days = tf_days
        self.tags = tags or []

    def run(self):
        if not HAS_THREAT_FEEDS:
            self.finished_signal.emit(0, 0)
            return
        try:
            sigs = update_all_feeds(
                use_malwarebazaar=self.use_mb,
                use_threatfox=self.use_tf,
                malwarebazaar_limit=self.mb_limit,
                threatfox_days=self.tf_days,
                tags=self.tags,
                log_callback=self.log_signal.emit
            )
            if sigs:
                added, skipped = merge_signatures_to_db(sigs, self.log_signal.emit)
                config = load_auto_update_config()
                config["last_update"] = datetime.datetime.now().isoformat()
                save_auto_update_config(config)
                self.finished_signal.emit(added, skipped)
            else:
                self.log_signal.emit("⚠️ Сигнатур не получено")
                self.finished_signal.emit(0, 0)
        except Exception as e:
            self.log_signal.emit(f"❌ {e}")
            self.finished_signal.emit(0, 0)


class AutoUpdateScheduler(QThread):
    trigger_update = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        while self.running:
            try:
                config = load_auto_update_config()
                if config.get("enabled", True):
                    hours_passed = hours_since_last_update(config)
                    interval = config.get("interval_hours", 6)
                    if hours_passed >= interval:
                        self.trigger_update.emit()
                # 10 минут проверка
                for _ in range(600):
                    if not self.running:
                        return
                    self.msleep(1000)
            except Exception as e:
                print(f"Планировщик: {e}")
                self.msleep(60000)

    def stop(self):
        self.running = False
        self.wait(2000)


# ==========================================
# КОМПОНЕНТЫ
# ==========================================

class LimitedTextEdit(QTextEdit):
    """QTextEdit с ограничением размера лога"""
    
    def __init__(self, max_lines=MAX_LOG_LINES):
        super().__init__()
        self.max_lines = max_lines
        self.setReadOnly(True)
    
    def append(self, text):
        super().append(text)
        # Ограничиваем количество строк
        doc = self.document()
        if doc.blockCount() > self.max_lines:
            cursor = self.textCursor()
            cursor.movePosition(cursor.Start)
            cursor.movePosition(
                cursor.Down, cursor.KeepAnchor,
                doc.blockCount() - self.max_lines
            )
            cursor.removeSelectedText()


# ==========================================
# ГЛАВНОЕ ОКНО
# ==========================================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"🛡️ {APP_NAME} v{APP_VERSION}")

        screen = QDesktopWidget().screenGeometry()
        self.resize(int(screen.width() * 0.85), int(screen.height() * 0.85))
        self.center_on_screen()

        central = QWidget()
        layout = QVBoxLayout(central)

        # Верхняя панель
        top_panel = QHBoxLayout()
        self.admin_label = QLabel()
        self.update_admin_status()
        top_panel.addWidget(self.admin_label)
        top_panel.addStretch()
        self.last_update_label = QLabel()
        self.update_last_update_label()
        top_panel.addWidget(self.last_update_label)
        layout.addLayout(top_panel)

        # Вкладки
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        self.init_scan_tab()
        self.init_process_tab()
        self.init_signatures_tab()
        if HAS_THREAT_FEEDS:
            self.init_feeds_tab()
        self.init_system_tab()

        # Потоки
        self.proc_thread = ProcessUpdateThread(interval=2)
        self.proc_thread.updated.connect(self.refresh_processes)
        self.proc_thread.start()

        self.scan_thread = None
        self.feeds_thread = None
        self.scheduler = None
        
        if HAS_THREAT_FEEDS:
            self.start_auto_updater()

        self.setCentralWidget(central)
        self.process_data = {}

        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_last_update_label)
        self.update_timer.start(60000)

    def update_admin_status(self):
        if is_admin():
            self.admin_label.setText("✅ Запущено с правами администратора")
            self.admin_label.setStyleSheet(
                "color: green; font-weight: bold; padding: 5px;"
            )
        else:
            self.admin_label.setText("⚠️ БЕЗ прав администратора")
            self.admin_label.setStyleSheet(
                "color: orange; font-weight: bold; padding: 5px;"
            )

    def update_last_update_label(self):
        try:
            config = load_auto_update_config()
            last = config.get("last_update", "")
            if not last:
                text = "🌐 База никогда не обновлялась"
                color = "red"
            else:
                hours = hours_since_last_update(config)
                if hours < 1:
                    text = f"🌐 Обновлено {int(hours*60)} мин назад"
                    color = "green"
                elif hours < 24:
                    text = f"🌐 Обновлено {int(hours)} ч назад"
                    color = "green"
                else:
                    text = f"🌐 Обновлено {int(hours/24)} дн назад"
                    color = "orange"
            self.last_update_label.setText(text)
            self.last_update_label.setStyleSheet(
                f"color: {color}; font-weight: bold; padding: 5px;"
            )
        except Exception:
            pass

    def center_on_screen(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def closeEvent(self, event):
        # Корректное завершение всех потоков
        if self.proc_thread:
            self.proc_thread.stop()
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.scan_thread.wait(2000)
        if self.scheduler:
            self.scheduler.stop()
        if self.feeds_thread and self.feeds_thread.isRunning():
            self.feeds_thread.wait(3000)
        clear_icon_cache()
        event.accept()

    def start_auto_updater(self):
        config = load_auto_update_config()
        if not config.get("enabled", True):
            return
        
        self.scheduler = AutoUpdateScheduler()
        self.scheduler.trigger_update.connect(self.run_auto_update)
        self.scheduler.start()
        
        if config.get("on_startup", True):
            hours = hours_since_last_update(config)
            min_hours = config.get("min_hours_since_last", 12)
            if hours >= min_hours:
                QTimer.singleShot(5000, self.run_auto_update)

    def run_auto_update(self):
        if self.feeds_thread and self.feeds_thread.isRunning():
            return
        
        config = load_auto_update_config()
        sources = config.get("sources", {})
        
        self.feeds_thread = FeedsUpdateThread(
            use_mb=sources.get("malwarebazaar", True),
            use_tf=sources.get("threatfox", True),
            mb_limit=sources.get("malwarebazaar_limit", 100),
            tf_days=sources.get("threatfox_days", 3),
            tags=sources.get("tags", []),
        )
        
        if hasattr(self, 'feeds_log'):
            self.feeds_thread.log_signal.connect(self.feeds_log.append)
        
        self.feeds_thread.finished_signal.connect(self._auto_update_finished)
        self.feeds_thread.start()

    def _auto_update_finished(self, added, skipped):
        self.update_last_update_label()
        if hasattr(self, 'update_sig_stats'):
            self.update_sig_stats()

    # === Сканирование ===

    def init_scan_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        h = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        h.addWidget(self.progress_bar)
        self.progress_label = QLabel("Готов")
        h.addWidget(self.progress_label)
        layout.addLayout(h)

        self.log = LimitedTextEdit(MAX_LOG_LINES)
        self.log.setStyleSheet("font-family: Consolas, monospace; font-size: 12px;")
        layout.addWidget(self.log)

        h2 = QHBoxLayout()
        btn = QPushButton("🔍 Сканировать папку")
        btn.setMinimumHeight(40)
        btn.clicked.connect(self.start_scan)
        h2.addWidget(btn)
        
        self.btn_stop_scan = QPushButton("⏹️ Остановить")
        self.btn_stop_scan.setMinimumHeight(40)
        self.btn_stop_scan.clicked.connect(self.stop_scan)
        self.btn_stop_scan.setEnabled(False)
        h2.addWidget(self.btn_stop_scan)
        
        btn2 = QPushButton("🗑️ Очистить лог")
        btn2.setMinimumHeight(40)
        btn2.clicked.connect(self.log.clear)
        h2.addWidget(btn2)
        layout.addLayout(h2)

        self.tabs.addTab(tab, "🔍 Сканирование")

    def start_scan(self):
        folder = QFileDialog.getExistingDirectory(self, "Выберите папку")
        if not folder:
            return
        if self.scan_thread and self.scan_thread.isRunning():
            QMessageBox.information(self, "Внимание", "Сканирование уже идёт")
            return
        
        self.log.clear()
        self.progress_bar.setValue(0)
        self.progress_label.setText("Сканирование...")
        self.btn_stop_scan.setEnabled(True)
        
        self.scan_thread = ScannerThread(folder)
        self.scan_thread.update_log.connect(self.log.append)
        self.scan_thread.progress_update.connect(self.progress_bar.setValue)
        self.scan_thread.finished.connect(self.show_threats)
        self.scan_thread.start()

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.log.append("⏹️ Сканирование остановлено")
            self.btn_stop_scan.setEnabled(False)

    def show_threats(self, threats):
        self.progress_label.setText("Завершено")
        self.btn_stop_scan.setEnabled(False)
        
        if not threats:
            self.log.append("\n✅ Угрозы не обнаружены!")
            QMessageBox.information(self, "Готово", "✅ Угрозы не обнаружены!")
            return

        for t in threats:
            action = QMessageBox.question(
                self, "🚨 Угроза",
                f"Файл: {t['name']}\nПуть: {t['path']}\n"
                f"Тип: {t['threat']}\nМетод: {t['method']}\n\n"
                f"Yes = Удалить | No = Карантин | Cancel = Пропустить",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel
            )
            if action == QMessageBox.Yes:
                if delete_file(t['path']):
                    self.log.append(f"✅ Удалён")
                else:
                    self.log.append(f"❌ Ошибка")
            elif action == QMessageBox.No:
                qp = move_to_quarantine(t['path'])
                if qp:
                    self.log.append(f"📦 Карантин: {qp}")

    # === Процессы ===

    def init_process_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        h = QHBoxLayout()
        h.addWidget(QLabel("🔎 Поиск:"))
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Имя процесса...")
        self.search_bar.textChanged.connect(self.filter_processes)
        h.addWidget(self.search_bar)
        layout.addLayout(h)

        self.proc_table = QTableWidget()
        self.proc_table.setColumnCount(7)
        self.proc_table.setHorizontalHeaderLabels([
            "", "Имя", "Пользователь", "CPU %", "Память", "Службы", "Действие"
        ])
        self.proc_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.proc_table.setAlternatingRowColors(True)
        self.proc_table.setSortingEnabled(True)
        self.proc_table.setIconSize(QSize(20, 20))
        self.proc_table.verticalHeader().setVisible(False)

        header = self.proc_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)
        header.resizeSection(0, 30)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        header.setSectionResizeMode(6, QHeaderView.Fixed)
        header.resizeSection(6, 100)

        layout.addWidget(self.proc_table)
        self.proc_info_label = QLabel("Процессов: 0")
        layout.addWidget(self.proc_info_label)

        self.tabs.addTab(tab, "📊 Процессы")

    def refresh_processes(self, processes):
        """Оптимизированное обновление таблицы — только изменённые ячейки"""
        self.proc_table.setSortingEnabled(False)
        self.proc_table.setUpdatesEnabled(False)
        
        try:
            self.proc_info_label.setText(f"Процессов: {len(processes)}")
            
            new_pids = {p['pid'] for p in processes}

            # Удаление завершённых
            rows_to_remove = []
            for row in range(self.proc_table.rowCount()):
                item = self.proc_table.item(row, 0)
                if item and item.data(Qt.UserRole) not in new_pids:
                    rows_to_remove.append(row)
            
            for row in reversed(rows_to_remove):
                self.proc_table.removeRow(row)

            # Существующие строки
            existing = {}
            for row in range(self.proc_table.rowCount()):
                item = self.proc_table.item(row, 0)
                if item:
                    pid = item.data(Qt.UserRole)
                    if pid:
                        existing[pid] = row

            for proc in processes:
                pid = proc['pid']
                is_new = pid not in existing
                
                if is_new:
                    row = self.proc_table.rowCount()
                    self.proc_table.insertRow(row)
                    existing[pid] = row
                else:
                    row = existing[pid]

                self.process_data[pid] = proc

                # Иконка (только для новых строк)
                if is_new:
                    icon = get_process_icon(
                        proc.get('exe_path', ''), proc.get('name', '')
                    )
                    icon_item = QTableWidgetItem()
                    icon_item.setIcon(icon)
                    icon_item.setData(Qt.UserRole, pid)
                    self.proc_table.setItem(row, 0, icon_item)

                    name_item = QTableWidgetItem(proc['name'])
                    name_item.setData(Qt.UserRole, pid)
                    self.proc_table.setItem(row, 1, name_item)

                    self.proc_table.setItem(row, 2, QTableWidgetItem(proc['user'] or ""))

                # CPU - обновляем всегда
                cpu_text = f"{proc['cpu']:.1f}%"
                cpu_item = self.proc_table.item(row, 3)
                if cpu_item is None or cpu_item.text() != cpu_text:
                    cpu_item = QTableWidgetItem(cpu_text)
                    cpu_item.setTextAlignment(Qt.AlignCenter)
                    if proc['cpu'] > 50:
                        cpu_item.setBackground(QColor(255, 200, 200))
                    elif proc['cpu'] > 25:
                        cpu_item.setBackground(QColor(255, 230, 200))
                    self.proc_table.setItem(row, 3, cpu_item)

                # Память
                mem = proc['mem']
                mem_text = f"{mem/1024:.1f} GB" if mem > 1024 else f"{mem:.1f} MB"
                mem_item = self.proc_table.item(row, 4)
                if mem_item is None or mem_item.text() != mem_text:
                    mem_item = QTableWidgetItem(mem_text)
                    mem_item.setTextAlignment(Qt.AlignCenter)
                    self.proc_table.setItem(row, 4, mem_item)

                # Службы (только для новых)
                if is_new:
                    svcs = ", ".join(proc['services'][:3]) if proc['services'] else ""
                    if len(proc['services']) > 3:
                        svcs += f" (+{len(proc['services'])-3})"
                    self.proc_table.setItem(row, 5, QTableWidgetItem(svcs))

                # Подсветка строк (только для новых)
                if is_new:
                    if proc.get('is_self'):
                        color = QColor(173, 216, 230)
                    elif is_suspicious_process(proc['name']):
                        color = QColor(255, 180, 180)
                    else:
                        color = None
                    if color:
                        for col in range(6):
                            item = self.proc_table.item(row, col)
                            if item:
                                item.setBackground(color)

                    # Кнопка
                    btn = QPushButton("Завершить")
                    btn.setMinimumHeight(25)
                    if proc.get('is_self'):
                        btn.setEnabled(False)
                        btn.setText("(это я)")
                        btn.setStyleSheet("color: gray;")
                    else:
                        btn.clicked.connect(lambda checked, p=pid: self.kill_pid(p))
                        btn.setStyleSheet("""
                            QPushButton {
                                background-color: #ff6b6b; color: white;
                                border: none; border-radius: 3px;
                            }
                            QPushButton:hover { background-color: #ee5a5a; }
                        """)
                    self.proc_table.setCellWidget(row, 6, btn)
        finally:
            self.proc_table.setUpdatesEnabled(True)
            self.proc_table.setSortingEnabled(True)

    def filter_processes(self, text):
        text = text.lower()
        for row in range(self.proc_table.rowCount()):
            item = self.proc_table.item(row, 1)
            if item:
                self.proc_table.setRowHidden(
                    row, text not in item.text().lower()
                )

    def kill_pid(self, pid):
        info = self.process_data.get(pid, {})
        name = info.get('name', '?')
        reply = QMessageBox.question(
            self, "Подтверждение",
            f"Завершить процесс?\n\nИмя: {name}\nPID: {pid}",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        success, message = kill_process(pid)
        if success:
            self.log.append(f"✅ {message}")
            for row in range(self.proc_table.rowCount()):
                item = self.proc_table.item(row, 0)
                if item and item.data(Qt.UserRole) == pid:
                    self.proc_table.removeRow(row)
                    break
        else:
            self.log.append(f"❌ {message}")
            QMessageBox.warning(self, "Ошибка", message)

    # === Сигнатуры ===

    def init_signatures_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.sig_stats_label = QLabel()
        self.sig_stats_label.setStyleSheet(
            "padding: 10px; background: #f0f0f0; border-radius: 5px;"
        )
        layout.addWidget(self.sig_stats_label)
        self.update_sig_stats()

        # По файлу
        group1 = QGroupBox("📁 Добавить по файлу")
        form1 = QFormLayout(group1)

        self.sig_file_path = QLineEdit()
        btn_browse = QPushButton("Обзор...")
        btn_browse.clicked.connect(self.browse_sig_file)
        h1 = QHBoxLayout()
        h1.addWidget(self.sig_file_path)
        h1.addWidget(btn_browse)
        form1.addRow("Файл:", h1)

        self.sig_name_input = QLineEdit()
        form1.addRow("Название:", self.sig_name_input)

        self.sig_type_combo = QComboBox()
        self.sig_type_combo.addItems([
            "malware", "trojan", "miner", "ransomware",
            "adware", "pup", "worm", "rootkit", "spyware"
        ])
        form1.addRow("Тип:", self.sig_type_combo)

        self.sig_desc_input = QLineEdit()
        form1.addRow("Описание:", self.sig_desc_input)

        btn_add_file = QPushButton("➕ Добавить")
        btn_add_file.setMinimumHeight(35)
        btn_add_file.setStyleSheet(
            "background-color: #4CAF50; color: white; font-weight: bold;"
        )
        btn_add_file.clicked.connect(self.add_sig_from_file)
        form1.addRow(btn_add_file)
        layout.addWidget(group1)

        # По хэшу
        group2 = QGroupBox("🔑 По хэшу")
        form2 = QFormLayout(group2)

        self.sig_hash_input = QLineEdit()
        self.sig_hash_input.setPlaceholderText("MD5 (32) или SHA256 (64)")
        form2.addRow("Хэш:", self.sig_hash_input)

        self.sig_hash_name = QLineEdit()
        form2.addRow("Название:", self.sig_hash_name)

        self.sig_hash_type = QComboBox()
        self.sig_hash_type.addItems([
            "malware", "trojan", "miner", "ransomware",
            "adware", "pup", "worm", "rootkit", "spyware"
        ])
        form2.addRow("Тип:", self.sig_hash_type)

        btn_add_hash = QPushButton("➕ Добавить по хэшу")
        btn_add_hash.setMinimumHeight(35)
        btn_add_hash.setStyleSheet(
            "background-color: #2196F3; color: white; font-weight: bold;"
        )
        btn_add_hash.clicked.connect(self.add_sig_from_hash)
        form2.addRow(btn_add_hash)
        layout.addWidget(group2)

        # Утилиты
        group3 = QGroupBox("📦 Утилиты")
        h3 = QHBoxLayout(group3)
        for text, func in [
            ("📥 Импорт CSV", self.import_sigs_csv),
            ("📤 Экспорт CSV", self.export_sigs_csv),
            ("🔢 Хэш файла", self.calc_file_hash),
            ("🔄 Обновить", self.update_sig_stats),
        ]:
            btn = QPushButton(text)
            btn.clicked.connect(func)
            h3.addWidget(btn)
        layout.addWidget(group3)

        self.sig_log = LimitedTextEdit(500)
        self.sig_log.setMaximumHeight(150)
        self.sig_log.setStyleSheet("font-family: Consolas, monospace;")
        layout.addWidget(self.sig_log)

        self.tabs.addTab(tab, "🔑 Сигнатуры")

    def update_sig_stats(self):
        stats = get_stats()
        text = (
            f"📊 База: {stats['total']} сигнатур | "
            f"Обновлено: {stats['updated'] or 'никогда'}"
        )
        if stats['by_type']:
            types = ", ".join(f"{t}: {c}" for t, c in stats['by_type'].items())
            text += f"\n   По типам: {types}"
        self.sig_stats_label.setText(text)

    def browse_sig_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Файл", "", "Все (*.*)")
        if path:
            self.sig_file_path.setText(path)

    def add_sig_from_file(self):
        path = self.sig_file_path.text().strip()
        name = self.sig_name_input.text().strip()
        if not path or not name:
            QMessageBox.warning(self, "Ошибка", "Заполните поля")
            return
        success, msg = add_signature(
            path, name, self.sig_type_combo.currentText(),
            self.sig_desc_input.text().strip()
        )
        if success:
            self.sig_log.append(f"✅ {msg}")
            self.update_sig_stats()
            self.sig_file_path.clear()
            self.sig_name_input.clear()
        else:
            self.sig_log.append(f"❌ {msg}")

    def add_sig_from_hash(self):
        h = self.sig_hash_input.text().strip()
        name = self.sig_hash_name.text().strip()
        if not h or not name:
            QMessageBox.warning(self, "Ошибка", "Заполните поля")
            return
        success, msg = add_hash_manually(h, name, self.sig_hash_type.currentText())
        if success:
            self.sig_log.append(f"✅ {msg}")
            self.update_sig_stats()
        else:
            self.sig_log.append(f"❌ {msg}")

    def import_sigs_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "CSV", "", "CSV (*.csv)")
        if not path:
            return
        a, s, e = import_from_csv(path)
        self.sig_log.append(f"📥 +{a}, дублей {s}, ошибок {e}")
        self.update_sig_stats()

    def export_sigs_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Экспорт", "export.csv", "CSV (*.csv)")
        if not path:
            return
        success, count = export_to_csv(path)
        if success:
            self.sig_log.append(f"📤 Экспортировано {count}")

    def calc_file_hash(self):
        path, _ = QFileDialog.getOpenFileName(self, "Файл", "", "Все (*.*)")
        if not path:
            return
        hashes = compute_hashes(path)
        if hashes:
            self.sig_log.append(
                f"\n📁 {hashes['filename']}\n"
                f"   SHA256: {hashes['sha256']}\n"
                f"   MD5:    {hashes['md5']}"
            )

    # === Обновление базы ===

    def init_feeds_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        info = QLabel(
            "🌐 Автозагрузка сигнатур из открытых источников\n\n"
            "📌 Получите БЕСПЛАТНЫЙ Auth-Key: https://auth.abuse.ch/"
        )
        info.setWordWrap(True)
        info.setStyleSheet(
            "padding: 10px; background: #e3f2fd; "
            "border-radius: 5px; color: #1565c0;"
        )
        layout.addWidget(info)

        config = load_auto_update_config()

        # Автообновление
        group_auto = QGroupBox("⏰ Автообновление")
        auto_layout = QVBoxLayout(group_auto)

        self.cb_auto_enabled = QCheckBox("Включить")
        self.cb_auto_enabled.setChecked(config.get("enabled", True))
        self.cb_auto_enabled.stateChanged.connect(self.save_auto_config)
        auto_layout.addWidget(self.cb_auto_enabled)

        self.cb_auto_startup = QCheckBox("Обновлять при запуске")
        self.cb_auto_startup.setChecked(config.get("on_startup", True))
        self.cb_auto_startup.stateChanged.connect(self.save_auto_config)
        auto_layout.addWidget(self.cb_auto_startup)

        h_int = QHBoxLayout()
        h_int.addWidget(QLabel("Интервал (ч):"))
        self.auto_interval_spin = QSpinBox()
        self.auto_interval_spin.setRange(1, 168)
        self.auto_interval_spin.setValue(config.get("interval_hours", 6))
        self.auto_interval_spin.valueChanged.connect(self.save_auto_config)
        h_int.addWidget(self.auto_interval_spin)
        h_int.addStretch()
        auto_layout.addLayout(h_int)
        layout.addWidget(group_auto)

        # Источники
        group_sources = QGroupBox("📡 Источники")
        sg_layout = QVBoxLayout(group_sources)
        sources = config.get("sources", {})

        self.cb_malwarebazaar = QCheckBox("MalwareBazaar")
        self.cb_malwarebazaar.setChecked(sources.get("malwarebazaar", True))
        self.cb_malwarebazaar.stateChanged.connect(self.save_auto_config)
        sg_layout.addWidget(self.cb_malwarebazaar)

        h_mb = QHBoxLayout()
        h_mb.addWidget(QLabel("  Образцов:"))
        self.mb_limit_spin = QSpinBox()
        self.mb_limit_spin.setRange(10, 100)
        self.mb_limit_spin.setValue(sources.get("malwarebazaar_limit", 100))
        self.mb_limit_spin.valueChanged.connect(self.save_auto_config)
        h_mb.addWidget(self.mb_limit_spin)
        h_mb.addStretch()
        sg_layout.addLayout(h_mb)

        self.cb_threatfox = QCheckBox("ThreatFox")
        self.cb_threatfox.setChecked(sources.get("threatfox", True))
        self.cb_threatfox.stateChanged.connect(self.save_auto_config)
        sg_layout.addWidget(self.cb_threatfox)

        h_tf = QHBoxLayout()
        h_tf.addWidget(QLabel("  Дней:"))
        self.tf_days_spin = QSpinBox()
        self.tf_days_spin.setRange(1, 7)
        self.tf_days_spin.setValue(sources.get("threatfox_days", 3))
        self.tf_days_spin.valueChanged.connect(self.save_auto_config)
        h_tf.addWidget(self.tf_days_spin)
        h_tf.addStretch()
        sg_layout.addLayout(h_tf)

        sg_layout.addWidget(QLabel("Теги:"))
        self.tags_input = QLineEdit()
        self.tags_input.setText(", ".join(sources.get("tags", [])))
        self.tags_input.editingFinished.connect(self.save_auto_config)
        sg_layout.addWidget(self.tags_input)
        layout.addWidget(group_sources)

        # API ключи
        group_keys = QGroupBox("🔑 API ключи")
        keys_layout = QFormLayout(group_keys)

        self.abusech_key_input = QLineEdit()
        self.abusech_key_input.setEchoMode(QLineEdit.Password)
        keys_layout.addRow("abuse.ch:", self.abusech_key_input)

        hint = QLabel(
            '<a href="https://auth.abuse.ch/">📌 Получить Auth-Key</a>'
        )
        hint.setOpenExternalLinks(True)
        keys_layout.addRow("", hint)

        self.vt_key_input = QLineEdit()
        self.vt_key_input.setEchoMode(QLineEdit.Password)
        keys_layout.addRow("VirusTotal:", self.vt_key_input)

        btn_save_keys = QPushButton("💾 Сохранить ключи")
        btn_save_keys.clicked.connect(self.save_api_keys_ui)
        keys_layout.addRow(btn_save_keys)

        btn_test = QPushButton("🔌 Проверить подключение")
        btn_test.clicked.connect(self.test_abusech)
        keys_layout.addRow(btn_test)

        layout.addWidget(group_keys)
        self._load_api_keys_ui()

        # Проверка хэша
        group_check = QGroupBox("🔍 Проверить хэш через VT")
        check_layout = QHBoxLayout(group_check)
        self.check_hash_input = QLineEdit()
        check_layout.addWidget(self.check_hash_input)
        btn_check_vt = QPushButton("🔍 Проверить")
        btn_check_vt.clicked.connect(self.check_hash_vt)
        check_layout.addWidget(btn_check_vt)
        layout.addWidget(group_check)

        # Главная кнопка
        btn_update = QPushButton("🌐 ОБНОВИТЬ БАЗУ СЕЙЧАС")
        btn_update.setMinimumHeight(50)
        btn_update.setStyleSheet(
            "background-color: #4CAF50; color: white; "
            "font-weight: bold; font-size: 14px;"
        )
        btn_update.clicked.connect(self.manual_update_feeds)
        layout.addWidget(btn_update)

        self.feeds_log = LimitedTextEdit(500)
        self.feeds_log.setStyleSheet("font-family: Consolas, monospace; font-size: 11px;")
        layout.addWidget(self.feeds_log)

        self.tabs.addTab(tab, "🌐 Обновление базы")

    def save_auto_config(self):
        try:
            config = load_auto_update_config()
            config["enabled"] = self.cb_auto_enabled.isChecked()
            config["on_startup"] = self.cb_auto_startup.isChecked()
            config["interval_hours"] = self.auto_interval_spin.value()
            tags_text = self.tags_input.text().strip()
            tags = [t.strip() for t in tags_text.split(",") if t.strip()]
            config["sources"] = {
                "malwarebazaar": self.cb_malwarebazaar.isChecked(),
                "malwarebazaar_limit": self.mb_limit_spin.value(),
                "threatfox": self.cb_threatfox.isChecked(),
                "threatfox_days": self.tf_days_spin.value(),
                "tags": tags,
            }
            save_auto_update_config(config)
        except Exception as e:
            print(f"Конфиг: {e}")

    def _load_api_keys_ui(self):
        try:
            keys = load_api_keys()
            self.abusech_key_input.setText(keys.get("abusech", ""))
            self.vt_key_input.setText(keys.get("virustotal", ""))
        except Exception:
            pass

    def save_api_keys_ui(self):
        try:
            keys = load_api_keys()
            keys["abusech"] = self.abusech_key_input.text().strip()
            keys["virustotal"] = self.vt_key_input.text().strip()
            if save_api_keys(keys):
                self.feeds_log.append("✅ Ключи сохранены")
                QMessageBox.information(self, "Готово", "Сохранено!")
        except Exception as e:
            self.feeds_log.append(f"❌ {e}")

    def test_abusech(self):
        try:
            self.feeds_log.append("\n🔌 Проверка...")
            success, msg = test_abusech_connection(
                lambda m: self.feeds_log.append(m)
            )
            if success:
                self.feeds_log.append(f"✅ {msg}")
                QMessageBox.information(self, "OK", msg)
            else:
                self.feeds_log.append(f"❌ {msg}")
                QMessageBox.warning(
                    self, "Ошибка",
                    f"{msg}\n\nКлюч: https://auth.abuse.ch/"
                )
        except Exception as e:
            self.feeds_log.append(f"❌ {e}")

    def check_hash_vt(self):
        h = self.check_hash_input.text().strip()
        if not h:
            return
        try:
            keys = load_api_keys()
            vt_key = keys.get("virustotal", "")
            if not vt_key:
                QMessageBox.warning(self, "Ошибка", "Установите VT ключ")
                return
            self.feeds_log.append(f"\n🔍 {h[:16]}...")
            result = check_hash_virustotal(
                h, vt_key, lambda m: self.feeds_log.append(m)
            )
            if result:
                reply = QMessageBox.question(
                    self, "Добавить?",
                    f"🚨 Вредоносный!\n{result['name']}\n"
                    f"Детектов: {result['detections']}/{result['total_engines']}",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    merge_signatures_to_db([result], lambda m: self.feeds_log.append(m))
                    self.update_sig_stats()
            else:
                QMessageBox.information(self, "OK", "✅ Чистый")
        except Exception as e:
            self.feeds_log.append(f"❌ {e}")

    def manual_update_feeds(self):
        if self.feeds_thread and self.feeds_thread.isRunning():
            QMessageBox.information(self, "Внимание", "Уже обновляется")
            return
        
        keys = load_api_keys()
        if not keys.get("abusech", "").strip():
            QMessageBox.warning(
                self, "Нет ключа",
                "Установите Auth-Key abuse.ch:\nhttps://auth.abuse.ch/"
            )
            return
        
        self.save_auto_config()
        self.feeds_log.clear()
        self.feeds_log.append("⏳ Запуск...")
        
        tags_text = self.tags_input.text().strip()
        tags = [t.strip() for t in tags_text.split(",") if t.strip()]
        
        self.feeds_thread = FeedsUpdateThread(
            use_mb=self.cb_malwarebazaar.isChecked(),
            use_tf=self.cb_threatfox.isChecked(),
            mb_limit=self.mb_limit_spin.value(),
            tf_days=self.tf_days_spin.value(),
            tags=tags
        )
        self.feeds_thread.log_signal.connect(self.feeds_log.append)
        self.feeds_thread.finished_signal.connect(self._manual_update_finished)
        self.feeds_thread.start()

    def _manual_update_finished(self, added, skipped):
        self.feeds_log.append(f"\n✅ +{added}, дублей: {skipped}")
        self.update_sig_stats()
        self.update_last_update_label()
        QMessageBox.information(
            self, "Готово",
            f"Добавлено: {added}\nПропущено: {skipped}"
        )

    # === Восстановление ===

    def init_system_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        desc = QLabel(
            "🔧 Восстановление системы:\n"
            "• Диспетчер задач • Редактор реестра\n"
            "• Командная строка • SFC"
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(
            "padding: 10px; background: #f0f0f0; border-radius: 5px;"
        )
        layout.addWidget(desc)

        self.sys_log = LimitedTextEdit(500)
        layout.addWidget(self.sys_log)

        h = QHBoxLayout()
        btn1 = QPushButton("🔧 Восстановить систему")
        btn1.setMinimumHeight(40)
        btn1.clicked.connect(self.repair_system)
        h.addWidget(btn1)
        btn2 = QPushButton("🛠️ SFC")
        btn2.setMinimumHeight(40)
        btn2.clicked.connect(self.run_sfc)
        h.addWidget(btn2)
        layout.addLayout(h)

        self.tabs.addTab(tab, "🔧 Восстановление")

    def repair_system(self):
        self.sys_log.append("🔧 Запуск...")
        import winreg
        repairs = [
            (winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
             "DisableTaskMgr", 0, "Диспетчер задач"),
            (winreg.HKEY_CURRENT_USER,
             r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
             "DisableRegistryTools", 0, "Реестр"),
            (winreg.HKEY_CURRENT_USER,
             r"Software\Policies\Microsoft\Windows\System",
             "DisableCMD", 0, "CMD"),
        ]
        for hive, path, name, value, desc in repairs:
            try:
                try:
                    key = winreg.OpenKey(hive, path, 0, winreg.KEY_WRITE)
                except FileNotFoundError:
                    key = winreg.CreateKey(hive, path)
                winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
                winreg.CloseKey(key)
                self.sys_log.append(f"✅ {desc}")
            except Exception as e:
                self.sys_log.append(f"⚠️ {desc}: {e}")
        QMessageBox.information(self, "Готово", "Завершено!")

    def run_sfc(self):
        if not is_admin():
            QMessageBox.warning(self, "Ошибка", "Нужны права админа")
            return
        try:
            import subprocess
            subprocess.Popen(
                ["cmd", "/c", "sfc /scannow && pause"],
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            self.sys_log.append("✅ SFC запущен")
        except Exception as e:
            self.sys_log.append(f"❌ {e}")


# === Запуск ===

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setApplicationName(APP_NAME)
    app.setApplicationDisplayName(APP_NAME)

    if not is_admin():
        reply = QMessageBox.question(
            None, "Права администратора",
            f"{APP_NAME} требует права администратора.\n\n"
            "Перезапустить?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
        )
        if reply == QMessageBox.Yes:
            if run_as_admin():
                sys.exit(0)

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()