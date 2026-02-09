# gui/views/logs_view.py

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QTextEdit, QPushButton, QLabel, QComboBox, QLineEdit,
    QMessageBox, QCheckBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QTextCursor, QColor, QTextCharFormat


class LogsView(QWidget):
    """
    Вкладка логов
    
    Содержит:
    - Просмотр логов системы
    - Фильтрация по типу событий
    - Поиск по тексту
    - Автоматическое обновление
    """
    
    def __init__(self, daemon_client):
        super().__init__()
        self.daemon_client = daemon_client
        
        self.all_logs = []  # Все логи
        self.auto_refresh = False
        
        self.init_ui()
    
    def init_ui(self):
        """Инициализация интерфейса"""
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        
        # ========== Панель управления ==========
        control_panel = QGroupBox("Управление")
        control_layout = QVBoxLayout(control_panel)
        
        # Первая строка: фильтр и поиск
        filter_layout = QHBoxLayout()
        
        # Фильтр по типу события
        filter_layout.addWidget(QLabel("Фильтр:"))
        
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([
            "Все события",
            "SYSTEM_START / STOP",
            "MODE (Режимы)",
            "FILE (Файлы)",
            "VIOLATION (Нарушения)",
            "RESTORE (Восстановление)",
            "RANSOMWARE",
            "EMERGENCY",
            "ERROR",
            "WARNING"
        ])
        self.filter_combo.currentTextChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.filter_combo)
        
        filter_layout.addSpacing(20)
        
        # Поиск
        filter_layout.addWidget(QLabel("🔍 Поиск:"))
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Введите текст для поиска...")
        self.search_input.textChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.search_input)
        
        control_layout.addLayout(filter_layout)
        
        # Вторая строка: количество строк и обновление
        options_layout = QHBoxLayout()
        
        options_layout.addWidget(QLabel("Количество строк:"))
        
        self.lines_combo = QComboBox()
        self.lines_combo.addItems(["50", "100", "200", "500", "1000"])
        self.lines_combo.setCurrentText("100")
        options_layout.addWidget(self.lines_combo)
        
        options_layout.addSpacing(20)
        
        # Автообновление
        self.auto_refresh_checkbox = QCheckBox("Автообновление")
        self.auto_refresh_checkbox.stateChanged.connect(self.toggle_auto_refresh)
        options_layout.addWidget(self.auto_refresh_checkbox)
        
        options_layout.addStretch()
        
        # Кнопки
        btn_refresh = QPushButton("🔄 Обновить")
        btn_refresh.clicked.connect(self.refresh)
        options_layout.addWidget(btn_refresh)
        
        btn_clear_display = QPushButton("🗑️ Очистить экран")
        btn_clear_display.clicked.connect(self.clear_display)
        options_layout.addWidget(btn_clear_display)
        
        btn_export = QPushButton("💾 Экспорт")
        btn_export.clicked.connect(self.export_logs)
        options_layout.addWidget(btn_export)
        
        control_layout.addLayout(options_layout)
        
        main_layout.addWidget(control_panel)
        
        # ========== Информация ==========
        info_layout = QHBoxLayout()
        
        self.info_label = QLabel("Всего событий: 0")
        self.info_label.setFont(QFont("Arial", 10))
        info_layout.addWidget(self.info_label)
        
        info_layout.addStretch()
        
        self.filtered_label = QLabel("Отображено: 0")
        self.filtered_label.setFont(QFont("Arial", 10))
        info_layout.addWidget(self.filtered_label)
        
        main_layout.addLayout(info_layout)
        
        # ========== Область логов ==========
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFont(QFont("Courier New", 9))
        self.log_display.setLineWrapMode(QTextEdit.NoWrap)
        
        main_layout.addWidget(self.log_display)
        
        # ========== Легенда ==========
        legend_layout = QHBoxLayout()
        
        legend_items = [
            ("🟢", "Информация"),
            ("🟡", "Предупреждение"),
            ("🔴", "Критическое"),
            ("🚨", "Аварийное")
        ]
        
        for icon, text in legend_items:
            label = QLabel(f"{icon} {text}")
            label.setStyleSheet("font-size: 9pt;")
            legend_layout.addWidget(label)
        
        legend_layout.addStretch()
        
        main_layout.addLayout(legend_layout)
    
    def refresh(self):
        """Обновление логов"""
        if not self.daemon_client.is_connected:
            return
        
        # Получение количества строк
        lines = int(self.lines_combo.currentText())
        
        # Загрузка логов
        success, logs, error = self.daemon_client.get_logs(lines)
        
        if success:
            self.all_logs = logs
            self.info_label.setText(f"Всего событий: {len(logs)}")
            
            # Применение фильтра
            self.apply_filter()
        else:
            QMessageBox.warning(
                self,
                "Ошибка",
                f"Не удалось загрузить логи:\n{error}"
            )
    
    def apply_filter(self):
        """Применение фильтра и поиска"""
        filter_type = self.filter_combo.currentText()
        search_text = self.search_input.text().lower()
        
        # Фильтрация логов
        filtered_logs = []
        
        for log_line in self.all_logs:
            # Применение фильтра по типу
            if filter_type != "Все события":
                if not self.matches_filter(log_line, filter_type):
                    continue
            
            # Применение поиска
            if search_text and search_text not in log_line.lower():
                continue
            
            filtered_logs.append(log_line)
        
        # Обновление отображения
        self.update_display(filtered_logs)
        
        # Обновление счётчика
        self.filtered_label.setText(f"Отображено: {len(filtered_logs)}")
    
    def matches_filter(self, log_line: str, filter_type: str) -> bool:
        """Проверка соответствия лога фильтру"""
        log_upper = log_line.upper()
        
        if filter_type == "SYSTEM_START / STOP":
            return "SYSTEM_START" in log_upper or "SYSTEM_STOP" in log_upper
        
        elif filter_type == "MODE (Режимы)":
            return any(keyword in log_upper for keyword in [
                "INIT_MODE", "UPDATE_MODE", "EMERGENCY_MODE"
            ])
        
        elif filter_type == "FILE (Файлы)":
            return any(keyword in log_upper for keyword in [
                "FILE_ADDED", "FILE_VERIFIED", "FILE_MODIFIED"
            ])
        
        elif filter_type == "VIOLATION (Нарушения)":
            return "UNAUTHORIZED" in log_upper or "SUSPICIOUS" in log_upper
        
        elif filter_type == "RESTORE (Восстановление)":
            return "RESTORED" in log_upper or "BACKUP" in log_upper
        
        elif filter_type == "RANSOMWARE":
            return "RANSOMWARE" in log_upper or "MASS_MODIFICATION" in log_upper
        
        elif filter_type == "EMERGENCY":
            return "EMERGENCY" in log_upper
        
        elif filter_type == "ERROR":
            return "[ERROR]" in log_upper
        
        elif filter_type == "WARNING":
            return "[WARNING]" in log_upper
        
        return True
    
    def update_display(self, logs: list):
        """Обновление отображения логов"""
        self.log_display.clear()
        
        for log_line in logs:
            self.append_colored_log(log_line)
    
    def append_colored_log(self, log_line: str):
        """Добавление строки лога с цветовым кодированием"""
        # Определение цвета по уровню
        color = None
        prefix = ""
        
        log_upper = log_line.upper()
        
        if "EMERGENCY" in log_upper or "RANSOMWARE" in log_upper:
            color = QColor(255, 0, 0)  # Красный
            prefix = "🚨 "
        elif "CRITICAL" in log_upper or "UNAUTHORIZED" in log_upper:
            color = QColor(220, 0, 0)  # Тёмно-красный
            prefix = "🔴 "
        elif "WARNING" in log_upper or "SUSPICIOUS" in log_upper:
            color = QColor(255, 165, 0)  # Оранжевый
            prefix = "🟡 "
        elif "ERROR" in log_upper:
            color = QColor(255, 100, 100)  # Светло-красный
            prefix = "🔴 "
        else:
            color = QColor(100, 100, 100)  # Серый
            prefix = "🟢 "
        
        # Форматирование текста
        cursor = self.log_display.textCursor()
        cursor.movePosition(QTextCursor.End)
        
        fmt = QTextCharFormat()
        fmt.setForeground(color)
        
        cursor.insertText(prefix + log_line + "\n", fmt)
        
        # Автопрокрутка вниз
        self.log_display.setTextCursor(cursor)
        self.log_display.ensureCursorVisible()
    
    def clear_display(self):
        """Очистка экрана (не удаляет логи)"""
        self.log_display.clear()
    
    def toggle_auto_refresh(self, state):
        """Переключение автообновления"""
        self.auto_refresh = (state == Qt.Checked)
        
        if self.auto_refresh:
            # Обновление сразу
            self.refresh()
    
    def export_logs(self):
        """Экспорт логов в файл"""
        from PySide6.QtWidgets import QFileDialog
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить логи",
            f"secure_fs_guard_logs.txt",
            "Текстовые файлы (*.txt);;Все файлы (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(self.all_logs))
                
                QMessageBox.information(
                    self,
                    "Успех",
                    f"Логи сохранены:\n{file_path}"
                )
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Ошибка",
                    f"Не удалось сохранить логи:\n{e}"
                )