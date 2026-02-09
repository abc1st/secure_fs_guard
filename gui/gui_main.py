# gui/gui_main.py

#!/usr/bin/env python3
"""
Secure FS Guard - GUI
Графический интерфейс управления системой контроля целостности
"""

import sys
import os
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QStatusBar, QMessageBox, QLabel, QPushButton
)
from PySide6.QtCore import Qt, QTimer, Signal, QThread
from PySide6.QtGui import QIcon, QFont

# Импорт клиента IPC
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ipc_client import DaemonClient

# Импорт view модулей (создадим далее)
from views.main_window import MainView
from views.settings_view import SettingsView
from views.integrity_view import IntegrityView
from views.logs_view import LogsView


class SecureFSGuardGUI(QMainWindow):
    """
    Главное окно GUI
    
    Содержит:
    - Вкладки для разных разделов
    - Статусная строка
    - Подключение к службе
    """
    
    # Сигналы
    connection_status_changed = Signal(bool, str)
    
    def __init__(self):
        super().__init__()
        
        # Клиент для связи с службой
        self.daemon_client = DaemonClient()
        
        # Таймер обновления статуса
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        
        # Инициализация UI
        self.init_ui()
        
        # Попытка подключения к службе
        self.connect_to_daemon()
        
        # Запуск таймера обновления (каждые 2 секунды)
        self.status_timer.start(2000)
    
    def init_ui(self):
        """Инициализация интерфейса"""
        self.setWindowTitle("Secure FS Guard - Система контроля целостности")
        self.setMinimumSize(1000, 700)
        
        # Центральный виджет
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Главный layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        
        # Заголовок
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Вкладки
        self.tabs = QTabWidget()
        self.tabs.setFont(QFont("Arial", 10))
        
        # Создание view для вкладок
        self.main_view = MainView(self.daemon_client)
        self.settings_view = SettingsView(self.daemon_client)
        self.integrity_view = IntegrityView(self.daemon_client)
        self.logs_view = LogsView(self.daemon_client)
        
        # Добавление вкладок
        self.tabs.addTab(self.main_view, "📊 Главная")
        self.tabs.addTab(self.integrity_view, "🔒 Целостность")
        self.tabs.addTab(self.settings_view, "⚙️ Настройки")
        self.tabs.addTab(self.logs_view, "📝 Логи")
        
        main_layout.addWidget(self.tabs)
        
        # Статусная строка
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Индикатор подключения в статусной строке
        self.connection_indicator = QLabel("⚫ Не подключён")
        self.status_bar.addPermanentWidget(self.connection_indicator)
        
        # Связь сигналов
        self.connection_status_changed.connect(self.on_connection_status_changed)
    
    def create_header(self) -> QWidget:
        """Создание заголовка приложения"""
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 10)
        
        # Заголовок
        title = QLabel("🛡️ Secure FS Guard")
        title_font = QFont("Arial", 16, QFont.Bold)
        title.setFont(title_font)
        
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        # Кнопка переподключения
        reconnect_btn = QPushButton("🔄 Переподключиться")
        reconnect_btn.clicked.connect(self.connect_to_daemon)
        header_layout.addWidget(reconnect_btn)
        
        return header
    
    def connect_to_daemon(self):
        """Подключение к службе"""
        # Отключение если уже подключён
        if self.daemon_client.is_connected:
            self.daemon_client.disconnect()
        
        # Попытка подключения
        success, message = self.daemon_client.connect()
        
        if success:
            self.connection_status_changed.emit(True, "Подключено к службе")
            self.status_bar.showMessage("✓ Подключение к службе установлено", 3000)
            
            # Обновление данных во всех view
            self.refresh_all_views()
        else:
            self.connection_status_changed.emit(False, message)
            self.status_bar.showMessage(f"✗ {message}", 5000)
            
            # Показать диалог с ошибкой
            QMessageBox.warning(
                self,
                "Ошибка подключения",
                f"Не удалось подключиться к службе:\n{message}\n\n"
                "Убедитесь, что служба запущена:\n"
                "sudo systemctl start secure-fs-guard"
            )
    
    def on_connection_status_changed(self, connected: bool, message: str):
        """Обработка изменения статуса подключения"""
        if connected:
            self.connection_indicator.setText("🟢 Подключён")
            self.connection_indicator.setStyleSheet("color: green;")
        else:
            self.connection_indicator.setText("🔴 Не подключён")
            self.connection_indicator.setStyleSheet("color: red;")
    
    def update_status(self):
        """Периодическое обновление статуса"""
        if not self.daemon_client.is_connected:
            return
        
        # Проверка связи со службой
        if not self.daemon_client.ping():
            self.connection_status_changed.emit(False, "Потеряно соединение со службой")
            return
        
        # Обновление текущей активной вкладки
        current_widget = self.tabs.currentWidget()
        if hasattr(current_widget, 'refresh'):
            current_widget.refresh()
    
    def refresh_all_views(self):
        """Обновление всех view"""
        for i in range(self.tabs.count()):
            widget = self.tabs.widget(i)
            if hasattr(widget, 'refresh'):
                widget.refresh()
    
    def closeEvent(self, event):
        """Обработка закрытия окна"""
        # Отключение от службы
        if self.daemon_client.is_connected:
            self.daemon_client.disconnect()
        
        # Остановка таймера
        self.status_timer.stop()
        
        event.accept()


def main():
    """Главная функция"""
    app = QApplication(sys.argv)
    
    # Установка стиля
    app.setStyle("Fusion")
    
    # Создание главного окна
    window = SecureFSGuardGUI()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()