# gui/views/integrity_view.py

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QTableWidget, QTableWidgetItem, QPushButton, QMessageBox,
    QLabel, QHeaderView, QAbstractItemView, QLineEdit, QProgressDialog
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QColor, QFont


class FileCheckThread(QThread):
    """Поток для проверки файла"""
    finished = Signal(bool, dict, str)
    
    def __init__(self, daemon_client, file_path):
        super().__init__()
        self.daemon_client = daemon_client
        self.file_path = file_path
    
    def run(self):
        success, data, error = self.daemon_client.check_file(self.file_path)
        self.finished.emit(success, data or {}, error)


class IntegrityView(QWidget):
    """
    Вкладка целостности
    
    Содержит:
    - Список всех защищённых файлов
    - Статус целостности каждого файла
    - Действия: проверка, восстановление
    """
    
    def __init__(self, daemon_client):
        super().__init__()
        self.daemon_client = daemon_client
        
        self.files_data = []  # Список файлов
        
        self.init_ui()
    
    def init_ui(self):
        """Инициализация интерфейса"""
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        
        # ========== Информация ==========
        info_group = QGroupBox("Информация")
        info_layout = QHBoxLayout(info_group)
        
        self.total_files_label = QLabel("Всего файлов: 0")
        self.total_files_label.setFont(QFont("Arial", 10, QFont.Bold))
        info_layout.addWidget(self.total_files_label)
        
        info_layout.addStretch()
        
        main_layout.addWidget(info_group)
        
        # ========== Поиск ==========
        search_layout = QHBoxLayout()
        
        search_layout.addWidget(QLabel("🔍 Поиск:"))
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Введите путь к файлу...")
        self.search_input.textChanged.connect(self.filter_files)
        search_layout.addWidget(self.search_input)
        
        main_layout.addLayout(search_layout)
        
        # ========== Таблица файлов ==========
        self.files_table = QTableWidget()
        self.files_table.setColumnCount(5)
        self.files_table.setHorizontalHeaderLabels([
            "Путь к файлу",
            "Размер",
            "Блоков",
            "Обновлён",
            "Статус"
        ])
        
        # Настройка таблицы
        self.files_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.files_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.files_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.files_table.setAlternatingRowColors(True)
        
        # Растягивание колонок
        header = self.files_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        
        main_layout.addWidget(self.files_table)
        
        # ========== Кнопки действий ==========
        actions_layout = QHBoxLayout()
        
        btn_check = QPushButton("🔍 Проверить выбранный")
        btn_check.clicked.connect(self.check_selected_file)
        actions_layout.addWidget(btn_check)
        
        btn_restore = QPushButton("🔄 Восстановить выбранный")
        btn_restore.clicked.connect(self.restore_selected_file)
        btn_restore.setStyleSheet("background-color: #FF9800; color: white;")
        actions_layout.addWidget(btn_restore)
        
        btn_info = QPushButton("ℹ️ Подробная информация")
        btn_info.clicked.connect(self.show_file_info)
        actions_layout.addWidget(btn_info)
        
        actions_layout.addStretch()
        
        btn_refresh = QPushButton("🔄 Обновить список")
        btn_refresh.clicked.connect(self.refresh)
        actions_layout.addWidget(btn_refresh)
        
        main_layout.addLayout(actions_layout)
    
    def refresh(self):
        """Обновление списка файлов"""
        if not self.daemon_client.is_connected:
            return
        
        # Получение списка файлов
        success, files, error = self.daemon_client.get_files()
        
        if not success:
            QMessageBox.warning(
                self,
                "Ошибка",
                f"Не удалось загрузить список файлов:\n{error}"
            )
            return
        
        # Сохранение данных
        self.files_data = []
        
        # Загрузка информации о каждом файле
        for file_path in files:
            success, info, error = self.daemon_client.get_file_info(file_path)
            
            if success:
                self.files_data.append(info)
        
        # Обновление таблицы
        self.update_table()
        
        # Обновление счётчика
        self.total_files_label.setText(f"Всего файлов: {len(self.files_data)}")
    
    def update_table(self):
        """Обновление таблицы файлов"""
        # Фильтрация по поисковому запросу
        search_text = self.search_input.text().lower()
        
        if search_text:
            filtered_data = [
                f for f in self.files_data
                if search_text in f['file_path'].lower()
            ]
        else:
            filtered_data = self.files_data
        
        # Заполнение таблицы
        self.files_table.setRowCount(len(filtered_data))
        
        for row, file_info in enumerate(filtered_data):
            # Путь
            path_item = QTableWidgetItem(file_info['file_path'])
            self.files_table.setItem(row, 0, path_item)
            
            # Размер
            size = file_info['file_size']
            size_str = self.format_size(size)
            size_item = QTableWidgetItem(size_str)
            size_item.setTextAlignment(Qt.AlignCenter)
            self.files_table.setItem(row, 1, size_item)
            
            # Блоков
            blocks_item = QTableWidgetItem(str(file_info['blocks_count']))
            blocks_item.setTextAlignment(Qt.AlignCenter)
            self.files_table.setItem(row, 2, blocks_item)
            
            # Обновлён
            updated = file_info['updated_at'].split('T')[0]  # Только дата
            updated_item = QTableWidgetItem(updated)
            updated_item.setTextAlignment(Qt.AlignCenter)
            self.files_table.setItem(row, 3, updated_item)
            
            # Статус
            is_trusted = file_info['is_trusted']
            status_item = QTableWidgetItem("✓ Доверенный" if is_trusted else "⚠️ Не доверенный")
            status_item.setTextAlignment(Qt.AlignCenter)
            
            if is_trusted:
                status_item.setForeground(QColor("green"))
            else:
                status_item.setForeground(QColor("red"))
            
            self.files_table.setItem(row, 4, status_item)
    
    def filter_files(self):
        """Фильтрация файлов по поисковому запросу"""
        self.update_table()
    
    def format_size(self, size: int) -> str:
        """Форматирование размера файла"""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.1f} GB"
    
    def get_selected_file_path(self) -> str:
        """Получение пути выбранного файла"""
        current_row = self.files_table.currentRow()
        
        if current_row < 0:
            return None
        
        path_item = self.files_table.item(current_row, 0)
        return path_item.text() if path_item else None
    
    def check_selected_file(self):
        """Проверка целостности выбранного файла"""
        file_path = self.get_selected_file_path()
        
        if not file_path:
            QMessageBox.warning(
                self,
                "Предупреждение",
                "Выберите файл для проверки"
            )
            return
        
        # Создание диалога прогресса
        progress = QProgressDialog("Проверка целостности...", None, 0, 0, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setWindowTitle("Проверка")
        progress.show()
        
        # Запуск проверки в отдельном потоке
        self.check_thread = FileCheckThread(self.daemon_client, file_path)
        self.check_thread.finished.connect(lambda success, data, error: self.on_check_finished(success, data, error, progress))
        self.check_thread.start()
    
    def on_check_finished(self, success: bool, data: dict, error: str, progress: QProgressDialog):
        """Обработка результата проверки"""
        progress.close()
        
        if success:
            change_type = data.get('change_type', 'UNKNOWN')
            blocks_changed = data.get('blocks_changed', 0)
            change_percent = data.get('change_percent', 0.0)
            entropy = data.get('entropy', 0.0)
            message = data.get('message', '')
            
            result_text = f"Результат проверки:\n\n"
            result_text += f"Тип изменения: {change_type}\n"
            result_text += f"Изменено блоков: {blocks_changed}\n"
            result_text += f"Процент изменений: {change_percent:.1f}%\n"
            result_text += f"Энтропия: {entropy:.2f}\n\n"
            result_text += f"{message}"
            
            if change_type == "NO_CHANGE":
                QMessageBox.information(self, "Целостность подтверждена", result_text)
            elif change_type == "ALLOWED_CHANGE":
                QMessageBox.information(self, "Допустимое изменение", result_text)
            else:
                QMessageBox.warning(self, "Обнаружено изменение", result_text)
        else:
            QMessageBox.critical(
                self,
                "Ошибка",
                f"Не удалось проверить файл:\n{error}"
            )
    
    def restore_selected_file(self):
        """Восстановление выбранного файла"""
        file_path = self.get_selected_file_path()
        
        if not file_path:
            QMessageBox.warning(
                self,
                "Предупреждение",
                "Выберите файл для восстановления"
            )
            return
        
        reply = QMessageBox.question(
            self,
            "Подтверждение",
            f"Восстановить файл из резервной копии?\n\n{file_path}\n\n"
            "⚠️ Текущая версия файла будет заменена эталонной версией!",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            success, message, error = self.daemon_client.restore_file(file_path)
            
            if success:
                QMessageBox.information(
                    self,
                    "Успех",
                    f"Файл восстановлен:\n{file_path}"
                )
            else:
                QMessageBox.critical(
                    self,
                    "Ошибка",
                    f"Не удалось восстановить файл:\n{error}"
                )
    
    def show_file_info(self):
        """Показ подробной информации о файле"""
        file_path = self.get_selected_file_path()
        
        if not file_path:
            QMessageBox.warning(
                self,
                "Предупреждение",
                "Выберите файл для просмотра информации"
            )
            return
        
        success, info, error = self.daemon_client.get_file_info(file_path)
        
        if success:
            info_text = f"Путь: {info['file_path']}\n\n"
            info_text += f"Размер: {self.format_size(info['file_size'])}\n"
            info_text += f"Блоков: {info['blocks_count']}\n"
            info_text += f"Доверенный: {'Да' if info['is_trusted'] else 'Нет'}\n"
            info_text += f"Создан: {info['created_at']}\n"
            info_text += f"Обновлён: {info['updated_at']}\n"
            info_text += f"Резервная копия: {info['backup_path'] or 'Нет'}\n"
            
            QMessageBox.information(
                self,
                "Информация о файле",
                info_text
            )
        else:
            QMessageBox.critical(
                self,
                "Ошибка",
                f"Не удалось получить информацию:\n{error}"
            )