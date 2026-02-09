# gui/views/main_window.py

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QPushButton, QGroupBox, QProgressBar, QFrame
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QPalette, QColor

class StatusCard(QFrame):
    """Карточка статуса с иконкой и информацией"""
    
    def __init__(self, title: str, icon: str = ""):
        super().__init__()
        self.setFrameStyle(QFrame.Box | QFrame.Raised)
        self.setLineWidth(2)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Заголовок с иконкой
        header_layout = QHBoxLayout()
        
        if icon:
            icon_label = QLabel(icon)
            icon_label.setFont(QFont("Arial", 24))
            header_layout.addWidget(icon_label)
        
        title_label = QLabel(title)
        title_label.setFont(QFont("Arial", 12, QFont.Bold))
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # Значение
        self.value_label = QLabel("—")
        self.value_label.setFont(QFont("Arial", 20, QFont.Bold))
        self.value_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.value_label)
        
        # Описание
        self.description_label = QLabel("")
        self.description_label.setFont(QFont("Arial", 9))
        self.description_label.setAlignment(Qt.AlignCenter)
        self.description_label.setWordWrap(True)
        layout.addWidget(self.description_label)
    
    def set_value(self, value: str, color: str = None):
        """Установка значения"""
        self.value_label.setText(value)
        if color:
            self.value_label.setStyleSheet(f"color: {color};")
    
    def set_description(self, description: str):
        """Установка описания"""
        self.description_label.setText(description)


class ModeIndicator(QWidget):
    """Индикатор текущего режима работы"""
    
    def __init__(self):
        super().__init__()
        
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Индикатор
        self.indicator = QLabel("⚫")
        self.indicator.setFont(QFont("Arial", 16))
        layout.addWidget(self.indicator)
        
        # Текст режима
        self.mode_label = QLabel("Неизвестно")
        self.mode_label.setFont(QFont("Arial", 12, QFont.Bold))
        layout.addWidget(self.mode_label)
        
        layout.addStretch()
    
    def set_mode(self, mode: str):
        """Установка режима"""
        mode_config = {
            'MONITOR': ('🟢', 'Режим контроля', 'green'),
            'INIT': ('🟡', 'Режим инициализации', 'orange'),
            'UPDATE': ('🟡', 'Режим обновления', 'orange'),
            'EMERGENCY': ('🔴', 'АВАРИЙНЫЙ РЕЖИМ', 'red')
        }
        
        if mode in mode_config:
            icon, text, color = mode_config[mode]
            self.indicator.setText(icon)
            self.mode_label.setText(text)
            self.mode_label.setStyleSheet(f"color: {color};")
        else:
            self.indicator.setText("⚫")
            self.mode_label.setText("Неизвестно")
            self.mode_label.setStyleSheet("")


class MainView(QWidget):
    """
    Главная вкладка GUI
    
    Отображает:
    - Текущий режим работы
    - Статистику защиты
    - Индикаторы состояния
    - Быстрые действия
    """
    
    def __init__(self, daemon_client):
        super().__init__()
        self.daemon_client = daemon_client
        
        self.init_ui()
    
    def init_ui(self):
        """Инициализация интерфейса"""
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        
        # ========== Режим работы ==========
        mode_group = QGroupBox("Текущий режим работы")
        mode_layout = QVBoxLayout(mode_group)
        
        self.mode_indicator = ModeIndicator()
        mode_layout.addWidget(self.mode_indicator)
        
        # Информация о режиме
        self.mode_info_label = QLabel("")
        self.mode_info_label.setWordWrap(True)
        mode_layout.addWidget(self.mode_info_label)
        
        # Кнопки управления режимами
        mode_buttons_layout = QHBoxLayout()
        
        self.btn_init_mode = QPushButton("🔧 Режим инициализации")
        self.btn_init_mode.clicked.connect(self.toggle_init_mode)
        mode_buttons_layout.addWidget(self.btn_init_mode)
        
        self.btn_update_mode = QPushButton("📝 Режим обновления")
        self.btn_update_mode.clicked.connect(self.toggle_update_mode)
        mode_buttons_layout.addWidget(self.btn_update_mode)
        
        self.btn_emergency_exit = QPushButton("🚨 Выйти из аварийного режима")
        self.btn_emergency_exit.clicked.connect(self.exit_emergency_mode)
        self.btn_emergency_exit.setVisible(False)
        mode_buttons_layout.addWidget(self.btn_emergency_exit)
        
        mode_layout.addLayout(mode_buttons_layout)
        
        main_layout.addWidget(mode_group)
        
        # ========== Статистика в карточках ==========
        stats_layout = QGridLayout()
        stats_layout.setSpacing(10)
        
        # Карточка: Защищённые файлы
        self.card_protected_files = StatusCard("Защищённые файлы", "📁")
        stats_layout.addWidget(self.card_protected_files, 0, 0)
        
        # Карточка: Проверено файлов
        self.card_checked_files = StatusCard("Проверено файлов", "✓")
        stats_layout.addWidget(self.card_checked_files, 0, 1)
        
        # Карточка: Нарушения
        self.card_violations = StatusCard("Нарушения", "⚠️")
        stats_layout.addWidget(self.card_violations, 1, 0)
        
        # Карточка: Восстановлено
        self.card_restored = StatusCard("Восстановлено", "🔄")
        stats_layout.addWidget(self.card_restored, 1, 1)
        
        main_layout.addLayout(stats_layout)
        
        # ========== Состояние мониторинга ==========
        monitoring_group = QGroupBox("Мониторинг файловой системы")
        monitoring_layout = QVBoxLayout(monitoring_group)
        
        # Статус
        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Статус:"))
        self.monitoring_status_label = QLabel("—")
        self.monitoring_status_label.setFont(QFont("Arial", 10, QFont.Bold))
        status_layout.addWidget(self.monitoring_status_label)
        status_layout.addStretch()
        monitoring_layout.addLayout(status_layout)
        
        # Информация
        info_layout = QGridLayout()
        
        info_layout.addWidget(QLabel("inotify:"), 0, 0)
        self.inotify_label = QLabel("—")
        info_layout.addWidget(self.inotify_label, 0, 1)
        
        info_layout.addWidget(QLabel("Отслеживаемых файлов:"), 1, 0)
        self.watched_files_label = QLabel("—")
        info_layout.addWidget(self.watched_files_label, 1, 1)
        
        info_layout.addWidget(QLabel("Защищаемых путей:"), 2, 0)
        self.protected_paths_label = QLabel("—")
        info_layout.addWidget(self.protected_paths_label, 2, 1)
        
        monitoring_layout.addLayout(info_layout)
        
        # Кнопки управления мониторингом
        monitoring_buttons = QHBoxLayout()
        
        self.btn_pause_monitoring = QPushButton("⏸ Приостановить")
        self.btn_pause_monitoring.clicked.connect(self.toggle_monitoring)
        monitoring_buttons.addWidget(self.btn_pause_monitoring)
        
        monitoring_buttons.addStretch()
        
        monitoring_layout.addLayout(monitoring_buttons)
        
        main_layout.addWidget(monitoring_group)
        
        # ========== Быстрые действия ==========
        actions_group = QGroupBox("Быстрые действия")
        actions_layout = QHBoxLayout(actions_group)
        
        btn_initialize = QPushButton("🔨 Инициализировать эталон")
        btn_initialize.clicked.connect(self.initialize_baseline)
        actions_layout.addWidget(btn_initialize)
        
        btn_refresh = QPushButton("🔄 Обновить статус")
        btn_refresh.clicked.connect(self.refresh)
        actions_layout.addWidget(btn_refresh)
        
        actions_layout.addStretch()
        
        main_layout.addWidget(actions_group)
        
        # Растягивание
        main_layout.addStretch()
        
        # Текущее состояние
        self.current_mode = None
        self.is_monitoring_paused = False
    
    def refresh(self):
        """Обновление данных"""
        if not self.daemon_client.is_connected:
            return
        
        # Получение статуса
        success, status, error = self.daemon_client.get_status()
        if not success:
            return
        
        # Обновление режима
        mode = status.get('mode', 'MONITOR')
        self.current_mode = mode
        self.mode_indicator.set_mode(mode)
        
        # Информация о режиме
        mode_info = status.get('mode_info', {})
        remaining_time = mode_info.get('remaining_time')
        
        if mode == 'UPDATE' and remaining_time is not None:
            self.mode_info_label.setText(f"Оставшееся время: {remaining_time} секунд")
        elif mode == 'EMERGENCY':
            reason = mode_info.get('emergency_reason', 'Неизвестно')
            self.mode_info_label.setText(f"Причина: {reason}")
        else:
            self.mode_info_label.setText("")
        
        # Обновление кнопок режимов
        self.update_mode_buttons(mode)
        
        # Статистика
        stats = status.get('statistics', {})
        self.card_protected_files.set_value(str(status.get('protected_files', 0)), "blue")
        self.card_checked_files.set_value(str(stats.get('files_checked', 0)), "green")
        
        violations = stats.get('violations_detected', 0)
        self.card_violations.set_value(str(violations), "red" if violations > 0 else "green")
        
        restored = stats.get('files_restored', 0)
        self.card_restored.set_value(str(restored), "orange" if restored > 0 else "green")
        
        # Мониторинг
        monitoring = status.get('monitoring', {})
        is_running = monitoring.get('is_running', False)
        is_paused = monitoring.get('is_paused', False)
        
        if is_running and not is_paused:
            self.monitoring_status_label.setText("🟢 Активен")
            self.monitoring_status_label.setStyleSheet("color: green;")
            self.btn_pause_monitoring.setText("⏸ Приостановить")
            self.is_monitoring_paused = False
        elif is_running and is_paused:
            self.monitoring_status_label.setText("🟡 Приостановлен")
            self.monitoring_status_label.setStyleSheet("color: orange;")
            self.btn_pause_monitoring.setText("▶️ Возобновить")
            self.is_monitoring_paused = True
        else:
            self.monitoring_status_label.setText("🔴 Остановлен")
            self.monitoring_status_label.setStyleSheet("color: red;")
        
        inotify_enabled = monitoring.get('inotify_enabled', False)
        self.inotify_label.setText("✓ Включён" if inotify_enabled else "✗ Выключен")
        
        self.watched_files_label.setText(str(monitoring.get('watched_files_count', 0)))
        self.protected_paths_label.setText(str(monitoring.get('protected_paths_count', 0)))
    
    def update_mode_buttons(self, mode: str):
        """Обновление кнопок в зависимости от режима"""
        if mode == 'INIT':
            self.btn_init_mode.setText("✓ Выйти из режима инициализации")
            self.btn_update_mode.setEnabled(False)
            self.btn_emergency_exit.setVisible(False)
        elif mode == 'UPDATE':
            self.btn_update_mode.setText("✓ Выйти из режима обновления")
            self.btn_init_mode.setEnabled(False)
            self.btn_emergency_exit.setVisible(False)
        elif mode == 'EMERGENCY':
            self.btn_init_mode.setEnabled(False)
            self.btn_update_mode.setEnabled(False)
            self.btn_emergency_exit.setVisible(True)
        else:  # MONITOR
            self.btn_init_mode.setText("🔧 Режим инициализации")
            self.btn_init_mode.setEnabled(True)
            self.btn_update_mode.setText("📝 Режим обновления")
            self.btn_update_mode.setEnabled(True)
            self.btn_emergency_exit.setVisible(False)
    
    def toggle_init_mode(self):
        """Переключение режима инициализации"""
        if self.current_mode == 'INIT':
            # Выход из режима
            success, message, error = self.daemon_client.exit_init_mode()
            if success:
                self.show_success_message("Режим инициализации завершён")
            else:
                self.show_error_message(f"Ошибка выхода из режима: {error}")
        else:
            # Вход в режим
            from PySide6.QtWidgets import QMessageBox
            reply = QMessageBox.question(
                self,
                "Подтверждение",
                "Войти в режим инициализации?\n\n"
                "В этом режиме вы сможете создать эталонное состояние файлов.",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                success, message, error = self.daemon_client.enter_init_mode()
                if success:
                    self.show_success_message("Режим инициализации включён")
                else:
                    self.show_error_message(f"Ошибка входа в режим: {error}")
        
        self.refresh()
    
    def toggle_update_mode(self):
        """Переключение режима обновления"""
        if self.current_mode == 'UPDATE':
            # Выход из режима
            success, message, error = self.daemon_client.exit_update_mode()
            if success:
                self.show_success_message("Режим обновления завершён")
            else:
                self.show_error_message(f"Ошибка выхода из режима: {error}")
        else:
            # Вход в режим
            from PySide6.QtWidgets import QMessageBox, QInputDialog
            
            timeout, ok = QInputDialog.getInt(
                self,
                "Режим обновления",
                "Время режима обновления (секунды):",
                300, 60, 3600, 60
            )
            
            if ok:
                reply = QMessageBox.warning(
                    self,
                    "Подтверждение",
                    f"Войти в режим обновления на {timeout} секунд?\n\n"
                    "⚠️ В этом режиме изменения файлов будут считаться легитимными!\n"
                    "Мониторинг будет приостановлен.",
                    QMessageBox.Yes | QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                    success, message, error = self.daemon_client.enter_update_mode(timeout)
                    if success:
                        self.show_success_message(f"Режим обновления включён на {timeout} сек")
                    else:
                        self.show_error_message(f"Ошибка входа в режим: {error}")
        
        self.refresh()
    
    def exit_emergency_mode(self):
        """Выход из аварийного режима"""
        from PySide6.QtWidgets import QMessageBox
        
        reply = QMessageBox.warning(
            self,
            "Подтверждение",
            "Выйти из аварийного режима?\n\n"
            "Убедитесь, что угроза устранена!",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            success, message, error = self.daemon_client.exit_emergency_mode()
            if success:
                self.show_success_message("Аварийный режим деактивирован")
            else:
                self.show_error_message(f"Ошибка выхода из режима: {error}")
            
            self.refresh()
    
    def toggle_monitoring(self):
        """Переключение паузы мониторинга"""
        if self.is_monitoring_paused:
            success, data, error = self.daemon_client.send_command(
                self.daemon_client.IPCCommand.RESUME_MONITORING
            )
        else:
            success, data, error = self.daemon_client.send_command(
                self.daemon_client.IPCCommand.PAUSE_MONITORING
            )
        
        if success:
            self.refresh()
        else:
            self.show_error_message(f"Ошибка: {error}")
    
    def initialize_baseline(self):
        """Инициализация эталонного состояния"""
        from PySide6.QtWidgets import QMessageBox
        
        if self.current_mode != 'INIT':
            QMessageBox.warning(
                self,
                "Требуется режим инициализации",
                "Для инициализации эталона необходимо войти в режим инициализации."
            )
            return
        
        reply = QMessageBox.question(
            self,
            "Подтверждение",
            "Начать инициализацию эталонного состояния?\n\n"
            "Это может занять некоторое время в зависимости от количества файлов.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            success, message, error = self.daemon_client.initialize_baseline()
            if success:
                self.show_success_message("Инициализация запущена")
            else:
                self.show_error_message(f"Ошибка: {error}")
    
    def show_success_message(self, message: str):
        """Показ сообщения об успехе"""
        from PySide6.QtWidgets import QMessageBox
        QMessageBox.information(self, "Успех", message)
    
    def show_error_message(self, message: str):
        """Показ сообщения об ошибке"""
        from PySide6.QtWidgets import QMessageBox
        QMessageBox.critical(self, "Ошибка", message)