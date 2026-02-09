# gui/views/settings_view.py

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QListWidget, QListWidgetItem, QPushButton, QFileDialog,
    QMessageBox, QLabel, QLineEdit, QSpinBox, QDoubleSpinBox,
    QFormLayout, QCheckBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont


class SettingsView(QWidget):
    """
    Вкладка настроек
    
    Содержит:
    - Управление защищаемыми путями
    - Конфигурация пороговых значений
    - Параметры мониторинга
    """
    
    def __init__(self, daemon_client):
        super().__init__()
        self.daemon_client = daemon_client
        
        self.init_ui()
    
    def init_ui(self):
        """Инициализация интерфейса"""
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        
        # ========== Защищаемые пути ==========
        paths_group = QGroupBox("Защищаемые пути")
        paths_layout = QVBoxLayout(paths_group)
        
        # Описание
        description = QLabel(
            "Список директорий и файлов, находящихся под защитой системы.\n"
            "Изменения этих файлов будут отслеживаться и контролироваться."
        )
        description.setWordWrap(True)
        description.setStyleSheet("color: gray;")
        paths_layout.addWidget(description)
        
        # Список путей
        self.paths_list = QListWidget()
        self.paths_list.setMinimumHeight(200)
        paths_layout.addWidget(self.paths_list)
        
        # Кнопки управления путями
        paths_buttons = QHBoxLayout()
        
        btn_add_dir = QPushButton("📁 Добавить директорию")
        btn_add_dir.clicked.connect(self.add_directory)
        paths_buttons.addWidget(btn_add_dir)
        
        btn_add_file = QPushButton("📄 Добавить файл")
        btn_add_file.clicked.connect(self.add_file)
        paths_buttons.addWidget(btn_add_file)
        
        btn_remove = QPushButton("🗑️ Удалить выбранный")
        btn_remove.clicked.connect(self.remove_path)
        paths_buttons.addWidget(btn_remove)
        
        paths_buttons.addStretch()
        
        paths_layout.addLayout(paths_buttons)
        
        main_layout.addWidget(paths_group)
        
        # ========== Конфигурация ==========
        config_group = QGroupBox("Конфигурация системы")
        config_layout = QFormLayout(config_group)
        
        # Размер блока
        self.block_size_spin = QSpinBox()
        self.block_size_spin.setRange(4, 1024)
        self.block_size_spin.setValue(64)
        self.block_size_spin.setSuffix(" KB")
        self.block_size_spin.setEnabled(False)  # Только чтение (требует переинициализации)
        config_layout.addRow("Размер блока:", self.block_size_spin)
        
        # Fallback интервал
        self.fallback_interval_spin = QSpinBox()
        self.fallback_interval_spin.setRange(10, 600)
        self.fallback_interval_spin.setValue(60)
        self.fallback_interval_spin.setSuffix(" сек")
        config_layout.addRow("Интервал fallback проверки:", self.fallback_interval_spin)
        
        main_layout.addWidget(config_group)
        
        # ========== Пороги ransomware ==========
        ransomware_group = QGroupBox("Пороги обнаружения ransomware")
        ransomware_layout = QFormLayout(ransomware_group)
        
        # Количество файлов
        self.ransomware_files_spin = QSpinBox()
        self.ransomware_files_spin.setRange(1, 100)
        self.ransomware_files_spin.setValue(10)
        ransomware_layout.addRow("Количество файлов:", self.ransomware_files_spin)
        
        # Временное окно
        self.ransomware_time_spin = QSpinBox()
        self.ransomware_time_spin.setRange(1, 60)
        self.ransomware_time_spin.setValue(10)
        self.ransomware_time_spin.setSuffix(" сек")
        ransomware_layout.addRow("Временное окно:", self.ransomware_time_spin)
        
        # Процент изменённых блоков
        self.ransomware_blocks_spin = QSpinBox()
        self.ransomware_blocks_spin.setRange(10, 100)
        self.ransomware_blocks_spin.setValue(70)
        self.ransomware_blocks_spin.setSuffix(" %")
        ransomware_layout.addRow("Процент изменённых блоков:", self.ransomware_blocks_spin)
        
        # Порог энтропии
        self.ransomware_entropy_spin = QDoubleSpinBox()
        self.ransomware_entropy_spin.setRange(0.0, 8.0)
        self.ransomware_entropy_spin.setValue(7.5)
        self.ransomware_entropy_spin.setSingleStep(0.1)
        ransomware_layout.addRow("Порог энтропии:", self.ransomware_entropy_spin)
        
        # Описание
        ransomware_description = QLabel(
            "Если за указанное временное окно будет изменено указанное количество файлов\n"
            "с процентом изменённых блоков выше порога и энтропией выше порога,\n"
            "система определит это как атаку ransomware."
        )
        ransomware_description.setWordWrap(True)
        ransomware_description.setStyleSheet("color: gray; font-size: 9pt;")
        ransomware_layout.addRow(ransomware_description)
        
        main_layout.addWidget(ransomware_group)
        
        # ========== Кнопки действий ==========
        actions_layout = QHBoxLayout()
        
        btn_save = QPushButton("💾 Сохранить настройки")
        btn_save.clicked.connect(self.save_settings)
        btn_save.setStyleSheet("background-color: #4CAF50; color: white; padding: 8px;")
        actions_layout.addWidget(btn_save)
        
        btn_refresh = QPushButton("🔄 Обновить")
        btn_refresh.clicked.connect(self.refresh)
        actions_layout.addWidget(btn_refresh)
        
        actions_layout.addStretch()
        
        main_layout.addLayout(actions_layout)
        
        # Растягивание
        main_layout.addStretch()
    
    def refresh(self):
        """Обновление данных"""
        if not self.daemon_client.is_connected:
            return
        
        # Загрузка защищаемых путей
        self.load_protected_paths()
        
        # Загрузка конфигурации
        self.load_config()
    
    def load_protected_paths(self):
        """Загрузка списка защищаемых путей"""
        success, paths, error = self.daemon_client.get_paths()
        
        self.paths_list.clear()
        
        if success:
            for path in paths:
                item = QListWidgetItem(path)
                self.paths_list.addItem(item)
        else:
            QMessageBox.warning(
                self,
                "Ошибка",
                f"Не удалось загрузить список путей:\n{error}"
            )
    
    def load_config(self):
        """Загрузка конфигурации"""
        success, config, error = self.daemon_client.get_config()
        
        if success:
            # Размер блока
            block_size_kb = config.get('block_size', 65536) // 1024
            self.block_size_spin.setValue(block_size_kb)
            
            # Fallback интервал
            fallback = config.get('fallback_interval', 60)
            self.fallback_interval_spin.setValue(fallback)
            
            # Пороги ransomware
            thresholds = config.get('ransomware_thresholds', {})
            self.ransomware_files_spin.setValue(thresholds.get('files_count', 10))
            self.ransomware_time_spin.setValue(thresholds.get('time_window', 10))
            self.ransomware_blocks_spin.setValue(thresholds.get('block_change_percent', 70))
            self.ransomware_entropy_spin.setValue(thresholds.get('entropy_threshold', 7.5))
        else:
            QMessageBox.warning(
                self,
                "Ошибка",
                f"Не удалось загрузить конфигурацию:\n{error}"
            )
    
    def add_directory(self):
        """Добавление директории"""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Выберите директорию для защиты",
            "",
            QFileDialog.ShowDirsOnly
        )
        
        if directory:
            self.add_path(directory)
    
    def add_file(self):
        """Добавление файла"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите файл для защиты",
            "",
            "Все файлы (*)"
        )
        
        if file_path:
            self.add_path(file_path)
    
    def add_path(self, path: str):
        """Добавление пути в защиту"""
        success, message, error = self.daemon_client.add_path(path)
        
        if success:
            # Обновление списка
            self.load_protected_paths()
            
            QMessageBox.information(
                self,
                "Успех",
                f"Путь добавлен:\n{path}\n\n"
                "Не забудьте инициализировать эталонное состояние для новых файлов."
            )
        else:
            QMessageBox.critical(
                self,
                "Ошибка",
                f"Не удалось добавить путь:\n{error}"
            )
    
    def remove_path(self):
        """Удаление выбранного пути"""
        current_item = self.paths_list.currentItem()
        
        if not current_item:
            QMessageBox.warning(
                self,
                "Предупреждение",
                "Выберите путь для удаления"
            )
            return
        
        path = current_item.text()
        
        reply = QMessageBox.question(
            self,
            "Подтверждение",
            f"Удалить путь из защиты?\n\n{path}\n\n"
            "⚠️ Эталонное состояние файлов этого пути останется в базе данных.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            success, message, error = self.daemon_client.remove_path(path)
            
            if success:
                # Обновление списка
                self.load_protected_paths()
                
                QMessageBox.information(
                    self,
                    "Успех",
                    f"Путь удалён:\n{path}"
                )
            else:
                QMessageBox.critical(
                    self,
                    "Ошибка",
                    f"Не удалось удалить путь:\n{error}"
                )
    
    def save_settings(self):
        """Сохранение настроек"""
        # Формирование новой конфигурации
        new_config = {
            'fallback_interval': self.fallback_interval_spin.value(),
            'ransomware_thresholds': {
                'files_count': self.ransomware_files_spin.value(),
                'time_window': self.ransomware_time_spin.value(),
                'block_change_percent': self.ransomware_blocks_spin.value(),
                'entropy_threshold': self.ransomware_entropy_spin.value()
            }
        }
        
        # Отправка обновлённой конфигурации
        success, data, error = self.daemon_client.send_command(
            self.daemon_client.IPCCommand.UPDATE_CONFIG,
            new_config
        )
        
        if success:
            QMessageBox.information(
                self,
                "Успех",
                "Настройки сохранены.\n\n"
                "⚠️ Некоторые изменения могут потребовать перезапуска демона."
            )
        else:
            QMessageBox.critical(
                self,
                "Ошибка",
                f"Не удалось сохранить настройки:\n{error}"
            )