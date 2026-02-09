# daemon/logger.py

import logging
import os
from pathlib import Path
from datetime import datetime
from enum import Enum
from typing import Optional
from logging.handlers import RotatingFileHandler

class EventType(Enum):
    """Типы событий системы безопасности"""
    SYSTEM_START = "SYSTEM_START"
    SYSTEM_STOP = "SYSTEM_STOP"
    INIT_MODE_ENABLED = "INIT_MODE_ENABLED"
    INIT_MODE_DISABLED = "INIT_MODE_DISABLED"
    UPDATE_MODE_ENABLED = "UPDATE_MODE_ENABLED"
    UPDATE_MODE_DISABLED = "UPDATE_MODE_DISABLED"
    FILE_ADDED = "FILE_ADDED"
    FILE_VERIFIED = "FILE_VERIFIED"
    FILE_MODIFIED_ALLOWED = "FILE_MODIFIED_ALLOWED"
    FILE_MODIFIED_UNAUTHORIZED = "FILE_MODIFIED_UNAUTHORIZED"
    FILE_RESTORED = "FILE_RESTORED"
    FILE_BLOCKED = "FILE_BLOCKED"
    HASH_UPDATED = "HASH_UPDATED"
    BACKUP_CREATED = "BACKUP_CREATED"
    BACKUP_RESTORED = "BACKUP_RESTORED"
    RANSOMWARE_DETECTED = "RANSOMWARE_DETECTED"
    MASS_MODIFICATION_DETECTED = "MASS_MODIFICATION_DETECTED"
    EMERGENCY_MODE_ACTIVATED = "EMERGENCY_MODE_ACTIVATED"
    PROCESS_TERMINATED = "PROCESS_TERMINATED"
    CONFIG_CHANGED = "CONFIG_CHANGED"
    PATH_ADDED = "PATH_ADDED"
    PATH_REMOVED = "PATH_REMOVED"
    IPC_CONNECTED = "IPC_CONNECTED"
    IPC_DISCONNECTED = "IPC_DISCONNECTED"
    ADMIN_ACTION = "ADMIN_ACTION"
    ERROR = "ERROR"
    WARNING = "WARNING"

class EventSeverity(Enum):
    """Уровни критичности событий"""
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    EMERGENCY = "EMERGENCY"

class SecurityLogger:
    """
    Журнал безопасности системы
    
    Отвечает за:
    - логирование всех событий безопасности
    - ротацию логов
    - структурированное хранение событий
    """
    
    def __init__(self, log_path: str = "/var/log/secure_fs_guard/system.log"):
        self.log_path = log_path
        self.logger = None
        self._setup_logger()
    
    def _setup_logger(self):
        """Настройка логгера с ротацией"""
        # Создание директории для логов
        Path(os.path.dirname(self.log_path)).mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # Создание логгера
        self.logger = logging.getLogger('secure_fs_guard')
        self.logger.setLevel(logging.DEBUG)
        
        # Очистка существующих handlers
        self.logger.handlers.clear()
        
        # Rotating File Handler (максимум 10 MB, 5 файлов)
        file_handler = RotatingFileHandler(
            self.log_path,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        
        # Console Handler (для отладки)
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Формат логов
        formatter = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [%(event_type)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Установка прав доступа к лог-файлу (только root)
        if os.path.exists(self.log_path):
            os.chmod(self.log_path, 0o600)
    
    def _log(self, event_type: EventType, severity: EventSeverity, message: str, **kwargs):
        """
        Внутренний метод логирования
        
        Args:
            event_type: тип события
            severity: уровень критичности
            message: текст сообщения
            **kwargs: дополнительные параметры
        """
        # Формирование дополнительной информации
        extra_info = {
            'event_type': event_type.value,
            'severity': severity.value
        }
        
        # Добавление дополнительных полей
        if kwargs:
            details = ' | '.join([f"{k}={v}" for k, v in kwargs.items()])
            message = f"{message} | {details}"
        
        # Выбор уровня логирования
        if severity == EventSeverity.INFO:
            self.logger.info(message, extra=extra_info)
        elif severity == EventSeverity.WARNING:
            self.logger.warning(message, extra=extra_info)
        elif severity == EventSeverity.CRITICAL:
            self.logger.critical(message, extra=extra_info)
        elif severity == EventSeverity.EMERGENCY:
            self.logger.critical(f"🚨 EMERGENCY: {message}", extra=extra_info)
    
    # ========== События системы ==========
    
    def system_start(self):
        """Запуск системы"""
        self._log(EventType.SYSTEM_START, EventSeverity.INFO, "Система контроля целостности запущена")
    
    def system_stop(self):
        """Остановка системы"""
        self._log(EventType.SYSTEM_STOP, EventSeverity.INFO, "Система контроля целостности остановлена")
    
    # ========== Режимы работы ==========
    
    def init_mode_enabled(self, admin: str = "system"):
        """Включение режима инициализации"""
        self._log(EventType.INIT_MODE_ENABLED, EventSeverity.WARNING, 
                  "Режим инициализации эталонного состояния ВКЛЮЧЁН", admin=admin)
    
    def init_mode_disabled(self):
        """Выключение режима инициализации"""
        self._log(EventType.INIT_MODE_DISABLED, EventSeverity.INFO, 
                  "Режим инициализации ВЫКЛЮЧЕН, система в режиме контроля")
    
    def update_mode_enabled(self, admin: str = "system", timeout: int = 0):
        """Включение режима обновления"""
        self._log(EventType.UPDATE_MODE_ENABLED, EventSeverity.WARNING,
                  "Режим обновления эталона ВКЛЮЧЁН", admin=admin, timeout_sec=timeout)
    
    def update_mode_disabled(self):
        """Выключение режима обновления"""
        self._log(EventType.UPDATE_MODE_DISABLED, EventSeverity.INFO,
                  "Режим обновления ВЫКЛЮЧЕН, система в режиме контроля")
    
    # ========== Операции с файлами ==========
    
    def file_added(self, file_path: str, blocks_count: int):
        """Файл добавлен в доверенное состояние"""
        self._log(EventType.FILE_ADDED, EventSeverity.INFO,
                  f"Файл добавлен в доверенное состояние", path=file_path, blocks=blocks_count)
    
    def file_verified(self, file_path: str):
        """Файл прошёл проверку целостности"""
        self._log(EventType.FILE_VERIFIED, EventSeverity.INFO,
                  f"Целостность подтверждена", path=file_path)
    
    def file_modified_allowed(self, file_path: str, blocks_changed: int):
        """Допустимое изменение файла (режим обновления)"""
        self._log(EventType.FILE_MODIFIED_ALLOWED, EventSeverity.INFO,
                  "Допустимое изменение файла", path=file_path, blocks_changed=blocks_changed)
    
    def file_modified_unauthorized(self, file_path: str, blocks_changed: int, total_blocks: int):
        """Несанкционированное изменение файла"""
        change_percent = (blocks_changed / total_blocks * 100) if total_blocks > 0 else 0
        self._log(EventType.FILE_MODIFIED_UNAUTHORIZED, EventSeverity.CRITICAL,
                  "⚠️ НЕСАНКЦИОНИРОВАННОЕ ИЗМЕНЕНИЕ", 
                  path=file_path, 
                  blocks_changed=blocks_changed,
                  total_blocks=total_blocks,
                  change_percent=f"{change_percent:.1f}%")
    
    def file_restored(self, file_path: str, method: str = "backup"):
        """Файл восстановлен"""
        self._log(EventType.FILE_RESTORED, EventSeverity.WARNING,
                  "Файл восстановлен", path=file_path, method=method)
    
    def file_blocked(self, file_path: str):
        """Файл заблокирован"""
        self._log(EventType.FILE_BLOCKED, EventSeverity.CRITICAL,
                  "Файл заблокирован для предотвращения повреждения", path=file_path)
    
    def hash_updated(self, file_path: str, blocks_count: int):
        """Эталонные хэши обновлены"""
        self._log(EventType.HASH_UPDATED, EventSeverity.INFO,
                  "Эталонные хэши обновлены", path=file_path, blocks=blocks_count)
    
    def backup_created(self, file_path: str, backup_path: str):
        """Создана резервная копия"""
        self._log(EventType.BACKUP_CREATED, EventSeverity.INFO,
                  "Резервная копия создана", original=file_path, backup=backup_path)
    
    def backup_restored(self, file_path: str, backup_path: str):
        """Восстановление из резервной копии"""
        self._log(EventType.BACKUP_RESTORED, EventSeverity.WARNING,
                  "Восстановление из резервной копии", original=file_path, backup=backup_path)
    
    # ========== Обнаружение атак ==========
    
    def ransomware_detected(self, affected_files: int, time_window: float, avg_entropy: float = 0.0):
        """Обнаружена атака ransomware"""
        self._log(EventType.RANSOMWARE_DETECTED, EventSeverity.EMERGENCY,
                  "🚨 ОБНАРУЖЕНА АТАКА RANSOMWARE",
                  affected_files=affected_files,
                  time_window_sec=f"{time_window:.2f}",
                  avg_entropy=f"{avg_entropy:.2f}")
    
    def mass_modification_detected(self, files_count: int, time_window: float):
        """Обнаружена массовая модификация"""
        self._log(EventType.MASS_MODIFICATION_DETECTED, EventSeverity.CRITICAL,
                  "⚠️ МАССОВАЯ МОДИФИКАЦИЯ ФАЙЛОВ",
                  files_count=files_count,
                  time_window_sec=f"{time_window:.2f}")
    
    def emergency_mode_activated(self, reason: str):
        """Активирован аварийный режим"""
        self._log(EventType.EMERGENCY_MODE_ACTIVATED, EventSeverity.EMERGENCY,
                  f"🚨 АВАРИЙНЫЙ РЕЖИМ АКТИВИРОВАН: {reason}")
    
    def process_terminated(self, pid: int, process_name: str, reason: str):
        """Процесс принудительно завершён"""
        self._log(EventType.PROCESS_TERMINATED, EventSeverity.CRITICAL,
                  "Процесс принудительно завершён",
                  pid=pid, process=process_name, reason=reason)
    
    # ========== Конфигурация ==========
    
    def config_changed(self, admin: str = "system", changes: str = ""):
        """Изменена конфигурация"""
        self._log(EventType.CONFIG_CHANGED, EventSeverity.WARNING,
                  "Конфигурация изменена", admin=admin, changes=changes)
    
    def path_added(self, path: str, admin: str = "system"):
        """Добавлен защищаемый путь"""
        self._log(EventType.PATH_ADDED, EventSeverity.INFO,
                  "Добавлен защищаемый путь", path=path, admin=admin)
    
    def path_removed(self, path: str, admin: str = "system"):
        """Удалён защищаемый путь"""
        self._log(EventType.PATH_REMOVED, EventSeverity.WARNING,
                  "Удалён защищаемый путь", path=path, admin=admin)
    
    # ========== IPC ==========
    
    def ipc_connected(self, client_info: str = ""):
        """Подключение GUI-клиента"""
        self._log(EventType.IPC_CONNECTED, EventSeverity.INFO,
                  "GUI-клиент подключён", client=client_info)
    
    def ipc_disconnected(self, client_info: str = ""):
        """Отключение GUI-клиента"""
        self._log(EventType.IPC_DISCONNECTED, EventSeverity.INFO,
                  "GUI-клиент отключён", client=client_info)
    
    # ========== Действия администратора ==========
    
    def admin_action(self, action: str, admin: str = "system", details: str = ""):
        """Действие администратора"""
        self._log(EventType.ADMIN_ACTION, EventSeverity.INFO,
                  f"Действие администратора: {action}", admin=admin, details=details)
    
    # ========== Ошибки и предупреждения ==========
    
    def error(self, message: str, **kwargs):
        """Ошибка системы"""
        self._log(EventType.ERROR, EventSeverity.CRITICAL,
                  f"Ошибка: {message}", **kwargs)
    
    def warning(self, message: str, **kwargs):
        """Предупреждение"""
        self._log(EventType.WARNING, EventSeverity.WARNING,
                  f"Предупреждение: {message}", **kwargs)
    
    # ========== Утилиты ==========
    
    def get_recent_logs(self, lines: int = 100) -> list:
        """
        Получение последних записей из лога
        
        Args:
            lines: количество строк
            
        Returns:
            список строк лога
        """
        try:
            if not os.path.exists(self.log_path):
                return []
            
            with open(self.log_path, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()
                return all_lines[-lines:] if len(all_lines) > lines else all_lines
        except Exception as e:
            return [f"Ошибка чтения лога: {e}"]
    
    def clear_logs(self):
        """Очистка логов (использовать с осторожностью)"""
        try:
            if os.path.exists(self.log_path):
                os.remove(self.log_path)
            self._setup_logger()
            self._log(EventType.ADMIN_ACTION, EventSeverity.WARNING,
                      "Логи очищены администратором")
        except Exception as e:
            self.error(f"Не удалось очистить логи: {e}")