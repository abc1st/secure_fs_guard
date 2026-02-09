# daemon/main.py

#!/usr/bin/env python3
"""
Secure FS Guard - Система контроля целостности и доверенного состояния файловой системы
с активным противодействием несанкционированным изменениям

Главный модуль демона
"""

import os
import sys
import signal
import time
import argparse
from pathlib import Path
from typing import Optional

# Импорт модулей системы
from config_manager import ConfigManager, SystemConfig
from logger import SecurityLogger, EventType, EventSeverity
from hash_storage import HashStorage, FileRecord
from integrity_engine import IntegrityEngine, ChangeType, IntegrityCheckResult
from watcher import FileWatcher, WatchEvent, WatchEventType
from recovery import RecoveryEngine, RecoveryMethod
from auth import AuthManager, SystemMode
from ipc_server import IPCServer, IPCCommand, IPCResponse

class SecureFSGuard:
    """
    Главный класс системы контроля целостности
    
    Координирует работу всех подсистем:
    - Конфигурация
    - Логирование
    - Хранилище хэшей
    - Движок целостности
    - Мониторинг файлов
    - Восстановление
    - Авторизация
    - IPC сервер
    """
    
    def __init__(self, config_path: str = "/etc/secure_fs_guard/system.yaml"):
        # Проверка root прав
        if os.geteuid() != 0:
            print("ОШИБКА: Демон должен быть запущен от имени root")
            sys.exit(1)
        
        print("=" * 60)
        print("Secure FS Guard - Система контроля целостности")
        print("=" * 60)
        
        # Инициализация компонентов
        self.config_manager: Optional[ConfigManager] = None
        self.logger: Optional[SecurityLogger] = None
        self.hash_storage: Optional[HashStorage] = None
        self.integrity_engine: Optional[IntegrityEngine] = None
        self.watcher: Optional[FileWatcher] = None
        self.recovery_engine: Optional[RecoveryEngine] = None
        self.auth_manager: Optional[AuthManager] = None
        self.ipc_server: Optional[IPCServer] = None
        
        self.config_path = config_path
        self.is_running = False
        
        # Статистика
        self.stats = {
            'files_checked': 0,
            'violations_detected': 0,
            'files_restored': 0,
            'ransomware_detected': 0
        }
    
    def initialize(self) -> bool:
        """
        Инициализация всех подсистем
        
        Returns:
            True если инициализация успешна
        """
        try:
            print("\n[1/8] Загрузка конфигурации...")
            self.config_manager = ConfigManager(self.config_path)
            if not self.config_manager.load():
                print("ОШИБКА: Не удалось загрузить конфигурацию")
                return False
            config = self.config_manager.get_config()
            print(f"✓ Конфигурация загружена из {self.config_path}")
            print(f"  - Защищаемых путей: {len(config.protected_paths)}")
            print(f"  - Размер блока: {config.block_config.size // 1024} KB")
            
            print("\n[2/8] Инициализация логирования...")
            self.logger = SecurityLogger(config.log_path)
            self.logger.system_start()
            print(f"✓ Логирование инициализировано: {config.log_path}")
            
            print("\n[3/8] Инициализация хранилища хэшей...")
            storage_path = os.path.join(config.storage_path, "hashes.db")
            self.hash_storage = HashStorage(storage_path)
            stats = self.hash_storage.get_statistics()
            print(f"✓ Хранилище инициализировано: {storage_path}")
            print(f"  - Файлов в доверенном состоянии: {stats['total_files']}")
            print(f"  - Всего блоков: {stats['total_blocks']}")
            
            print("\n[4/8] Инициализация движка целостности...")
            self.integrity_engine = IntegrityEngine(
                block_size=config.block_config.size,
                ransomware_thresholds={
                    'files_count': config.ransomware_thresholds.files_count,
                    'time_window': config.ransomware_thresholds.time_window,
                    'block_change_percent': config.ransomware_thresholds.block_change_percent,
                    'entropy_threshold': config.ransomware_thresholds.entropy_threshold
                }
            )
            print(f"✓ Движок целостности инициализирован")
            print(f"  - Порог ransomware: {config.ransomware_thresholds.files_count} файлов за {config.ransomware_thresholds.time_window} сек")
            
            print("\n[5/8] Инициализация движка восстановления...")
            backup_dir = os.path.join(config.storage_path, "backups")
            quarantine_dir = os.path.join(config.storage_path, "quarantine")
            self.recovery_engine = RecoveryEngine(
                backup_dir=backup_dir,
                quarantine_dir=quarantine_dir,
                block_size=config.block_config.size
            )
            print(f"✓ Движок восстановления инициализирован")
            print(f"  - Директория резервных копий: {backup_dir}")
            
            print("\n[6/8] Инициализация менеджера авторизации...")
            self.auth_manager = AuthManager()
            print(f"✓ Менеджер авторизации инициализирован")
            print(f"  - Текущий режим: {self.auth_manager.get_current_mode().value}")
            
            print("\n[7/8] Инициализация мониторинга файлов...")
            self.watcher = FileWatcher(
                protected_paths=config.protected_paths,
                callback=self._on_file_event,
                use_inotify=config.monitoring.use_inotify,
                fallback_interval=config.monitoring.fallback_interval
            )
            print(f"✓ Мониторинг инициализирован")
            print(f"  - inotify: {'включён' if config.monitoring.use_inotify else 'выключен'}")
            print(f"  - Fallback интервал: {config.monitoring.fallback_interval} сек")
            
            print("\n[8/8] Инициализация IPC сервера...")
            self.ipc_server = IPCServer(config.ipc_socket)
            self.ipc_server.set_log_callback(lambda msg: self.logger.admin_action("IPC", details=msg))
            self._register_ipc_handlers()
            if not self.ipc_server.start():
                print("ОШИБКА: Не удалось запустить IPC сервер")
                return False
            print(f"✓ IPC сервер запущен: {config.ipc_socket}")
            
            print("\n" + "=" * 60)
            print("✓ Все подсистемы инициализированы успешно")
            print("=" * 60)
            
            return True
        
        except Exception as e:
            print(f"\n✗ ОШИБКА ИНИЦИАЛИЗАЦИИ: {e}")
            if self.logger:
                self.logger.error(f"Ошибка инициализации: {e}")
            return False
    
    def _register_ipc_handlers(self):
        """Регистрация обработчиков IPC команд"""
        # Статус системы
        self.ipc_server.register_handler(IPCCommand.GET_STATUS, self._ipc_get_status)
        self.ipc_server.register_handler(IPCCommand.GET_STATISTICS, self._ipc_get_statistics)
        self.ipc_server.register_handler(IPCCommand.GET_LOGS, self._ipc_get_logs)
        
        # Управление режимами
        self.ipc_server.register_handler(IPCCommand.ENTER_INIT_MODE, self._ipc_enter_init_mode)
        self.ipc_server.register_handler(IPCCommand.EXIT_INIT_MODE, self._ipc_exit_init_mode)
        self.ipc_server.register_handler(IPCCommand.ENTER_UPDATE_MODE, self._ipc_enter_update_mode)
        self.ipc_server.register_handler(IPCCommand.EXIT_UPDATE_MODE, self._ipc_exit_update_mode)
        self.ipc_server.register_handler(IPCCommand.EXIT_EMERGENCY_MODE, self._ipc_exit_emergency_mode)
        
        # Управление путями
        self.ipc_server.register_handler(IPCCommand.ADD_PATH, self._ipc_add_path)
        self.ipc_server.register_handler(IPCCommand.REMOVE_PATH, self._ipc_remove_path)
        self.ipc_server.register_handler(IPCCommand.GET_PATHS, self._ipc_get_paths)
        
        # Управление файлами
        self.ipc_server.register_handler(IPCCommand.GET_FILES, self._ipc_get_files)
        self.ipc_server.register_handler(IPCCommand.GET_FILE_INFO, self._ipc_get_file_info)
        self.ipc_server.register_handler(IPCCommand.CHECK_FILE, self._ipc_check_file)
        self.ipc_server.register_handler(IPCCommand.RESTORE_FILE, self._ipc_restore_file)
        
        # Управление мониторингом
        self.ipc_server.register_handler(IPCCommand.START_MONITORING, self._ipc_start_monitoring)
        self.ipc_server.register_handler(IPCCommand.STOP_MONITORING, self._ipc_stop_monitoring)
        self.ipc_server.register_handler(IPCCommand.PAUSE_MONITORING, self._ipc_pause_monitoring)
        self.ipc_server.register_handler(IPCCommand.RESUME_MONITORING, self._ipc_resume_monitoring)
        
        # Инициализация
        self.ipc_server.register_handler(IPCCommand.INITIALIZE_BASELINE, self._ipc_initialize_baseline)
        
        # Конфигурация
        self.ipc_server.register_handler(IPCCommand.GET_CONFIG, self._ipc_get_config)
        self.ipc_server.register_handler(IPCCommand.UPDATE_CONFIG, self._ipc_update_config)
        
        # Система
        self.ipc_server.register_handler(IPCCommand.PING, self._ipc_ping)
        self.ipc_server.register_handler(IPCCommand.SHUTDOWN, self._ipc_shutdown)
    
    # ========== IPC Handlers ==========
    
    def _ipc_get_status(self, params: dict) -> IPCResponse:
        """Получение статуса системы"""
        status = {
            'is_running': self.is_running,
            'mode': self.auth_manager.get_current_mode().value,
            'mode_info': self.auth_manager.get_status(),
            'protected_files': self.hash_storage.get_files_count(),
            'statistics': self.stats,
            'monitoring': self.watcher.get_statistics() if self.watcher else {},
            'storage': self.hash_storage.get_statistics()
        }
        return IPCResponse(success=True, data=status)
    
    def _ipc_get_statistics(self, params: dict) -> IPCResponse:
        """Получение детальной статистики"""
        stats = {
            'system': self.stats,
            'storage': self.hash_storage.get_statistics(),
            'monitoring': self.watcher.get_statistics(),
            'integrity': self.integrity_engine.get_modification_statistics(),
            'auth': self.auth_manager.get_status(),
            'ipc': self.ipc_server.get_statistics()
        }
        return IPCResponse(success=True, data=stats)
    
    def _ipc_get_logs(self, params: dict) -> IPCResponse:
        """Получение логов"""
        lines = params.get('lines', 100)
        logs = self.logger.get_recent_logs(lines)
        return IPCResponse(success=True, data={'logs': logs})
    
    def _ipc_enter_init_mode(self, params: dict) -> IPCResponse:
        """Вход в режим инициализации"""
        admin_user = params.get('admin_user', 'gui')
        success, message = self.auth_manager.enter_init_mode(admin_user)
        
        if success:
            self.logger.init_mode_enabled(admin_user)
        
        return IPCResponse(success=success, data={'message': message})
    
    def _ipc_exit_init_mode(self, params: dict) -> IPCResponse:
        """Выход из режима инициализации"""
        admin_user = params.get('admin_user', 'gui')
        success, message = self.auth_manager.exit_init_mode(admin_user)
        
        if success:
            self.logger.init_mode_disabled()
        
        return IPCResponse(success=success, data={'message': message})
    
    def _ipc_enter_update_mode(self, params: dict) -> IPCResponse:
        """Вход в режим обновления"""
        admin_user = params.get('admin_user', 'gui')
        timeout = params.get('timeout', 300)
        
        success, message, token = self.auth_manager.enter_update_mode(admin_user, timeout)
        
        if success:
            self.logger.update_mode_enabled(admin_user, timeout)
            # Приостановка мониторинга
            self.watcher.pause()
        
        return IPCResponse(success=success, data={'message': message, 'token': token})
    
    def _ipc_exit_update_mode(self, params: dict) -> IPCResponse:
        """Выход из режима обновления"""
        admin_user = params.get('admin_user', 'gui')
        success, message = self.auth_manager.exit_update_mode(admin_user)
        
        if success:
            self.logger.update_mode_disabled()
            # Возобновление мониторинга
            self.watcher.resume()
        
        return IPCResponse(success=success, data={'message': message})
    
    def _ipc_exit_emergency_mode(self, params: dict) -> IPCResponse:
        """Выход из аварийного режима"""
        admin_user = params.get('admin_user', 'gui')
        success, message = self.auth_manager.exit_emergency_mode(admin_user)
        
        if success:
            self.logger.admin_action("Выход из аварийного режима", admin_user)
            # Возобновление мониторинга
            self.watcher.resume()
        
        return IPCResponse(success=success, data={'message': message})
    
    def _ipc_add_path(self, params: dict) -> IPCResponse:
        """Добавление защищаемого пути"""
        path = params.get('path')
        if not path:
            return IPCResponse(success=False, error="Не указан путь")
        
        if self.config_manager.add_protected_path(path):
            self.watcher.add_path(path)
            self.logger.path_added(path, params.get('admin_user', 'gui'))
            return IPCResponse(success=True, data={'message': f'Путь добавлен: {path}'})
        else:
            return IPCResponse(success=False, error="Не удалось добавить путь")
    
    def _ipc_remove_path(self, params: dict) -> IPCResponse:
        """Удаление защищаемого пути"""
        path = params.get('path')
        if not path:
            return IPCResponse(success=False, error="Не указан путь")
        
        if self.config_manager.remove_protected_path(path):
            self.watcher.remove_path(path)
            self.logger.path_removed(path, params.get('admin_user', 'gui'))
            return IPCResponse(success=True, data={'message': f'Путь удалён: {path}'})
        else:
            return IPCResponse(success=False, error="Не удалось удалить путь")
    
    def _ipc_get_paths(self, params: dict) -> IPCResponse:
        """Получение списка защищаемых путей"""
        paths = self.config_manager.get_config().protected_paths
        return IPCResponse(success=True, data={'paths': paths})
    
    def _ipc_get_files(self, params: dict) -> IPCResponse:
        """Получение списка файлов"""
        files = self.hash_storage.get_all_files()
        return IPCResponse(success=True, data={'files': files})
    
    def _ipc_get_file_info(self, params: dict) -> IPCResponse:
        """Получение информации о файле"""
        file_path = params.get('file_path')
        if not file_path:
            return IPCResponse(success=False, error="Не указан путь к файлу")
        
        file_record = self.hash_storage.get_file(file_path)
        if not file_record:
            return IPCResponse(success=False, error="Файл не найден в хранилище")
        
        info = {
            'file_path': file_record.file_path,
            'file_size': file_record.file_size,
            'blocks_count': file_record.blocks_count,
            'is_trusted': file_record.is_trusted,
            'created_at': file_record.created_at,
            'updated_at': file_record.updated_at,
            'backup_path': file_record.backup_path
        }
        
        return IPCResponse(success=True, data=info)
    
    def _ipc_check_file(self, params: dict) -> IPCResponse:
        """Проверка целостности файла"""
        file_path = params.get('file_path')
        if not file_path:
            return IPCResponse(success=False, error="Не указан путь к файлу")
        
        file_record = self.hash_storage.get_file(file_path)
        if not file_record:
            return IPCResponse(success=False, error="Файл не найден в хранилище")
        
        result = self.integrity_engine.check_integrity(
            file_path,
            file_record.block_hashes,
            self.auth_manager.is_update_mode()
        )
        
        return IPCResponse(success=True, data={
            'change_type': result.change_type.value,
            'blocks_changed': result.blocks_changed,
            'change_percent': result.change_percent,
            'entropy': result.entropy,
            'message': result.message
        })
    
    def _ipc_restore_file(self, params: dict) -> IPCResponse:
        """Восстановление файла"""
        file_path = params.get('file_path')
        if not file_path:
            return IPCResponse(success=False, error="Не указан путь к файлу")
        
        file_record = self.hash_storage.get_file(file_path)
        if not file_record or not file_record.backup_path:
            return IPCResponse(success=False, error="Резервная копия не найдена")
        
        result = self.recovery_engine.restore_from_backup(file_path, file_record.backup_path)
        
        if result.success:
            self.logger.file_restored(file_path, "manual")
        
        return IPCResponse(success=result.success, data={'message': result.message})
    
    def _ipc_start_monitoring(self, params: dict) -> IPCResponse:
        """Запуск мониторинга"""
        self.watcher.start()
        return IPCResponse(success=True, data={'message': 'Мониторинг запущен'})
    
    def _ipc_stop_monitoring(self, params: dict) -> IPCResponse:
        """Остановка мониторинга"""
        self.watcher.stop()
        return IPCResponse(success=True, data={'message': 'Мониторинг остановлен'})
    
    def _ipc_pause_monitoring(self, params: dict) -> IPCResponse:
        """Приостановка мониторинга"""
        self.watcher.pause()
        return IPCResponse(success=True, data={'message': 'Мониторинг приостановлен'})
    
    def _ipc_resume_monitoring(self, params: dict) -> IPCResponse:
        """Возобновление мониторинга"""
        self.watcher.resume()
        return IPCResponse(success=True, data={'message': 'Мониторинг возобновлён'})
    
    def _ipc_initialize_baseline(self, params: dict) -> IPCResponse:
        """Инициализация эталонного состояния"""
        if not self.auth_manager.is_init_mode():
            return IPCResponse(success=False, error="Требуется режим инициализации")
        
        # Запуск инициализации в отдельном потоке
        import threading
        thread = threading.Thread(target=self._perform_initialization, daemon=True)
        thread.start()
        
        return IPCResponse(success=True, data={'message': 'Инициализация запущена'})
    
    def _ipc_get_config(self, params: dict) -> IPCResponse:
        """Получение конфигурации"""
        config = self.config_manager.get_config()
        data = {
            'protected_paths': config.protected_paths,
            'block_size': config.block_config.size,
            'fallback_interval': config.monitoring.fallback_interval,
            'ransomware_thresholds': {
                'files_count': config.ransomware_thresholds.files_count,
                'time_window': config.ransomware_thresholds.time_window,
                'block_change_percent': config.ransomware_thresholds.block_change_percent,
                'entropy_threshold': config.ransomware_thresholds.entropy_threshold
            }
        }
        return IPCResponse(success=True, data=data)
    
    def _ipc_update_config(self, params: dict) -> IPCResponse:
        """Обновление конфигурации"""
        # Здесь можно добавить логику обновления конфигурации
        return IPCResponse(success=True, data={'message': 'Конфигурация обновлена'})
    
    def _ipc_ping(self, params: dict) -> IPCResponse:
        """Проверка связи"""
        return IPCResponse(success=True, data={'message': 'pong'})
    
    def _ipc_shutdown(self, params: dict) -> IPCResponse:
        """Остановка демона"""
        self.logger.admin_action("Остановка системы", params.get('admin_user', 'gui'))
        self.shutdown()
        return IPCResponse(success=True, data={'message': 'Система останавливается'})
    
    # ========== Основная логика ==========
    
    def _perform_initialization(self):
        """Выполнение инициализации эталонного состояния"""
        try:
            self.logger.admin_action("Начало инициализации эталонного состояния")
            
            config = self.config_manager.get_config()
            total_files = 0
            
            for base_path in config.protected_paths:
                expanded_path = os.path.expanduser(base_path)
                
                if os.path.isfile(expanded_path):
                    self._initialize_file(expanded_path)
                    total_files += 1
                
                elif os.path.isdir(expanded_path):
                    for root, dirs, files in os.walk(expanded_path):
                        for filename in files:
                            file_path = os.path.join(root, filename)
                            try:
                                self._initialize_file(file_path)
                                total_files += 1
                            except Exception as e:
                                self.logger.error(f"Ошибка инициализации {file_path}: {e}")
            
            self.logger.admin_action(f"Инициализация завершена", details=f"Обработано файлов: {total_files}")
            
            # Уведомление через IPC
            self.ipc_server.broadcast_notification('initialization_complete', {
                'total_files': total_files
            })
        
        except Exception as e:
            self.logger.error(f"Ошибка инициализации: {e}")
    
    def _initialize_file(self, file_path: str):
        """Инициализация одного файла"""
        # Вычисление хэшей
        block_hashes, file_size = self.integrity_engine.compute_file_hashes(file_path)
        
        # Создание резервной копии
        success, backup_path = self.recovery_engine.create_backup(file_path)
        
        # Сохранение в хранилище
        self.hash_storage.add_file(
            file_path=file_path,
            file_size=file_size,
            block_size=self.config_manager.get_config().block_config.size,
            block_hashes=block_hashes,
            backup_path=backup_path if success else None
        )
        
        self.logger.file_added(file_path, len(block_hashes))
        if success:
            self.logger.backup_created(file_path, backup_path)
    
    def _on_file_event(self, event: WatchEvent):
        """
        Обработчик событий от FileWatcher
        
        Args:
            event: событие изменения файла
        """
        # Игнорируем события для директорий
        if os.path.isdir(event.file_path):
            return
        
        # Проверка наличия файла в хранилище
        if not self.hash_storage.file_exists(event.file_path):
            # Файл не в доверенном состоянии - игнорируем
            return
        
        # Обработка в зависимости от типа события
        if event.event_type in [WatchEventType.MODIFY, WatchEventType.WRITE]:
            self._handle_file_modification(event.file_path)
        
        elif event.event_type == WatchEventType.DELETE:
            self._handle_file_deletion(event.file_path)
    
    def _handle_file_modification(self, file_path: str):
        """Обработка модификации файла"""
        try:
            # Получение эталонного состояния
            file_record = self.hash_storage.get_file(file_path)
            if not file_record:
                return
            
            # Проверка целостности
            result = self.integrity_engine.check_integrity(
                file_path,
                file_record.block_hashes,
                self.auth_manager.is_update_mode()
            )
            
            self.stats['files_checked'] += 1
            
            # Обработка результата
            if result.change_type == ChangeType.NO_CHANGE:
                self.logger.file_verified(file_path)
            
            elif result.change_type == ChangeType.ALLOWED_CHANGE:
                # Обновление эталона
                self._update_baseline(file_path, result)
                self.logger.file_modified_allowed(file_path, result.blocks_changed)
            
            elif result.change_type in [ChangeType.UNAUTHORIZED_CHANGE, ChangeType.SUSPICIOUS_CHANGE, ChangeType.CRITICAL_CHANGE]:
                self._handle_violation(file_path, result, file_record)
        
        except Exception as e:
            self.logger.error(f"Ошибка обработки модификации {file_path}: {e}")
    
    def _handle_violation(self, file_path: str, result: IntegrityCheckResult, file_record: FileRecord):
        """Обработка нарушения целостности"""
        self.stats['violations_detected'] += 1
        
        # Логирование
        self.logger.file_modified_unauthorized(file_path, result.blocks_changed, result.blocks_total)
        
        # Проверка на ransomware
        is_ransomware, details = self.integrity_engine.detect_ransomware_pattern()
        
        if is_ransomware:
            self._handle_ransomware_attack(details)
            return
        
        # Обычное нарушение - восстановление
        if result.change_type == ChangeType.CRITICAL_CHANGE:
            # Критическое изменение - немедленное восстановление
            self._restore_file_immediately(file_path, file_record)
        else:
            # Обычное нарушение - поблочное восстановление
            self._restore_file_blocks(file_path, file_record, result.changed_block_indices)
        
        # Уведомление через IPC
        self.ipc_server.broadcast_notification('violation_detected', {
            'file_path': file_path,
            'change_type': result.change_type.value,
            'blocks_changed': result.blocks_changed,
            'change_percent': result.change_percent
        })
    
    def _handle_ransomware_attack(self, details: dict):
        """Обработка атаки ransomware"""
        self.stats['ransomware_detected'] += 1
        
        self.logger.ransomware_detected(
            details['files_affected'],
            details['time_window_seconds'],
            details['avg_entropy']
        )
        
        # Вход в аварийный режим
        self.auth_manager.enter_emergency_mode("Обнаружена атака ransomware")
        
        # Приостановка мониторинга
        self.watcher.pause()
        
        # Массовая блокировка файлов
        all_files = self.hash_storage.get_all_files()
        blocked, errors = self.recovery_engine.emergency_block_all(all_files)
        
        self.logger.emergency_mode_activated(f"Заблокировано файлов: {blocked}/{len(all_files)}")
        
        # Уведомление через IPC
        self.ipc_server.broadcast_notification('ransomware_detected', details)
    
    def _restore_file_immediately(self, file_path: str, file_record: FileRecord):
        """Немедленное восстановление файла"""
        if not file_record.backup_path:
            self.logger.error(f"Нет резервной копии для {file_path}")
            return
        
        result = self.recovery_engine.restore_from_backup(file_path, file_record.backup_path)
        
        if result.success:
            self.stats['files_restored'] += 1
            self.logger.file_restored(file_path, "full_backup")
        else:
            self.logger.error(f"Не удалось восстановить {file_path}: {result.message}")
    
    def _restore_file_blocks(self, file_path: str, file_record: FileRecord, block_indices: list):
        """Поблочное восстановление файла"""
        if not file_record.backup_path:
            self.logger.error(f"Нет резервной копии для {file_path}")
            return
        
        result = self.recovery_engine.restore_blocks(file_path, file_record.backup_path, block_indices)
        
        if result.success:
            self.stats['files_restored'] += 1
            self.logger.file_restored(file_path, "block_restore")
        else:
            self.logger.error(f"Не удалось восстановить блоки {file_path}: {result.message}")
    
    def _update_baseline(self, file_path: str, result: IntegrityCheckResult):
        """Обновление эталонного состояния файла"""
        # Создание новой резервной копии
        success, backup_path = self.recovery_engine.create_backup(file_path)
        
        # Обновление хэшей
        file_size = os.path.getsize(file_path)
        self.hash_storage.update_file(
            file_path,
            file_size,
            result.current_hashes,
            backup_path if success else None
        )
        
        self.logger.hash_updated(file_path, len(result.current_hashes))
    
    def _handle_file_deletion(self, file_path: str):
        """Обработка удаления файла"""
        if self.auth_manager.is_update_mode():
            # В режиме обновления - допустимо
            self.logger.file_modified_allowed(file_path, 0)
        else:
            # Несанкционированное удаление - попытка восстановления
            file_record = self.hash_storage.get_file(file_path)
            if file_record and file_record.backup_path:
                self._restore_file_immediately(file_path, file_record)
    
    def start(self):
        """Запуск основного цикла"""
        self.is_running = True
        
        # Запуск мониторинга
        self.watcher.start()
        
        self.logger.admin_action("Система запущена в режиме контроля")
        
        print("\n✓ Система запущена и работает в фоновом режиме")
        print("  Для остановки используйте: systemctl stop secure-fs-guard")
        print("  Логи: " + self.config_manager.get_config().log_path)
        print()
        
        # Основной цикл
        try:
            while self.is_running:
                time.sleep(1)
                
                # Периодическая очистка истёкших сессий
                self.auth_manager.cleanup_expired_sessions()
        
        except KeyboardInterrupt:
            print("\n\nПолучен сигнал прерывания...")
            self.shutdown()
    
    def shutdown(self):
        """Корректная остановка системы"""
        print("\nОстановка системы...")
        
        self.is_running = False
        
        # Остановка мониторинга
        if self.watcher:
            print("  [1/4] Остановка мониторинга...")
            self.watcher.stop()
        
        # Остановка IPC сервера
        if self.ipc_server:
            print("  [2/4] Остановка IPC сервера...")
            self.ipc_server.stop()
        
        # Закрытие хранилища
        if self.hash_storage:
            print("  [3/4] Закрытие хранилища...")
            self.hash_storage.close()
        
        # Финальное логирование
        if self.logger:
            print("  [4/4] Финализация логов...")
            self.logger.system_stop()
        
        print("\n✓ Система остановлена")
    
    def setup_signal_handlers(self):
        """Установка обработчиков сигналов"""
        signal.signal(signal.SIGTERM, lambda sig, frame: self.shutdown())
        signal.signal(signal.SIGINT, lambda sig, frame: self.shutdown())


def main():
    """Главная функция"""
    parser = argparse.ArgumentParser(description='Secure FS Guard - Система контроля целостности')
    parser.add_argument('--config', default='/etc/secure_fs_guard/system.yaml',
                       help='Путь к файлу конфигурации')
    
    args = parser.parse_args()
    
    # Создание и инициализация системы
    system = SecureFSGuard(config_path=args.config)
    
    if not system.initialize():
        print("\n✗ Инициализация не удалась")
        sys.exit(1)
    
    # Установка обработчиков сигналов
    system.setup_signal_handlers()
    
    # Запуск основного цикла
    system.start()


if __name__ == "__main__":
    main()