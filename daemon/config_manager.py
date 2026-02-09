# daemon/config_manager.py

import yaml
import os
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, field

@dataclass
class BlockConfig:
    """Конфигурация блочного хеширования"""
    size: int = 64 * 1024  # 64 KB
    algorithm: str = "sha256"

@dataclass
class RansomwareThresholds:
    """Пороги определения ransomware-атаки"""
    files_count: int = 10  # количество файлов
    time_window: int = 10  # секунд
    block_change_percent: int = 70  # процент изменённых блоков
    entropy_threshold: float = 7.5  # порог энтропии (0-8)

@dataclass
class MonitoringConfig:
    """Конфигурация мониторинга"""
    fallback_interval: int = 60  # секунд
    use_inotify: bool = True

@dataclass
class SystemConfig:
    """Главная конфигурация системы"""
    protected_paths: List[str] = field(default_factory=list)
    block_config: BlockConfig = field(default_factory=BlockConfig)
    ransomware_thresholds: RansomwareThresholds = field(default_factory=RansomwareThresholds)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    storage_path: str = "/var/lib/secure_fs_guard/storage"
    log_path: str = "/var/log/secure_fs_guard/system.log"
    ipc_socket: str = "/var/run/secure_fs_guard.sock"
    update_mode: bool = False
    
class ConfigManager:
    """Менеджер конфигурации системы"""
    
    def __init__(self, config_path: str = "/etc/secure_fs_guard/system.yaml"):
        self.config_path = config_path
        self.config: SystemConfig = SystemConfig()
        self._ensure_directories()
        
    def _ensure_directories(self):
        """Создание необходимых директорий"""
        dirs = [
            os.path.dirname(self.config.storage_path),
            os.path.dirname(self.config.log_path),
            os.path.dirname(self.config.ipc_socket),
        ]
        
        for dir_path in dirs:
            Path(dir_path).mkdir(parents=True, exist_ok=True, mode=0o700)
    
    def load(self) -> bool:
        """
        Загрузка конфигурации из YAML-файла
        
        Returns:
            True если загрузка успешна, False иначе
        """
        try:
            if not os.path.exists(self.config_path):
                # Создаём конфигурацию по умолчанию
                self._create_default_config()
                return True
            
            with open(self.config_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data:
                return False
            
            # Загрузка защищаемых путей
            self.config.protected_paths = data.get('protected_paths', [])
            
            # Загрузка конфигурации блоков
            if 'block_config' in data:
                bc = data['block_config']
                self.config.block_config = BlockConfig(
                    size=bc.get('size', 64 * 1024),
                    algorithm=bc.get('algorithm', 'sha256')
                )
            
            # Загрузка порогов ransomware
            if 'ransomware_thresholds' in data:
                rt = data['ransomware_thresholds']
                self.config.ransomware_thresholds = RansomwareThresholds(
                    files_count=rt.get('files_count', 10),
                    time_window=rt.get('time_window', 10),
                    block_change_percent=rt.get('block_change_percent', 70),
                    entropy_threshold=rt.get('entropy_threshold', 7.5)
                )
            
            # Загрузка конфигурации мониторинга
            if 'monitoring' in data:
                mc = data['monitoring']
                self.config.monitoring = MonitoringConfig(
                    fallback_interval=mc.get('fallback_interval', 60),
                    use_inotify=mc.get('use_inotify', True)
                )
            
            # Остальные параметры
            self.config.storage_path = data.get('storage_path', self.config.storage_path)
            self.config.log_path = data.get('log_path', self.config.log_path)
            self.config.ipc_socket = data.get('ipc_socket', self.config.ipc_socket)
            
            return True
            
        except Exception as e:
            print(f"Ошибка загрузки конфигурации: {e}")
            return False
    
    def _create_default_config(self):
        """Создание конфигурации по умолчанию"""
        default_config = {
            'protected_paths': [
                '/home/*/Documents',
                '/home/*/important_data'
            ],
            'block_config': {
                'size': 65536,  # 64 KB
                'algorithm': 'sha256'
            },
            'ransomware_thresholds': {
                'files_count': 10,
                'time_window': 10,
                'block_change_percent': 70,
                'entropy_threshold': 7.5
            },
            'monitoring': {
                'fallback_interval': 60,
                'use_inotify': True
            },
            'storage_path': '/var/lib/secure_fs_guard/storage',
            'log_path': '/var/log/secure_fs_guard/system.log',
            'ipc_socket': '/var/run/secure_fs_guard.sock'
        }
        
        # Создание директории конфигурации
        Path(os.path.dirname(self.config_path)).mkdir(parents=True, exist_ok=True, mode=0o755)
        
        with open(self.config_path, 'w', encoding='utf-8') as f:
            yaml.dump(default_config, f, default_flow_style=False, allow_unicode=True)
    
    def save(self) -> bool:
        """
        Сохранение текущей конфигурации в файл
        
        Returns:
            True если сохранение успешно, False иначе
        """
        try:
            config_data = {
                'protected_paths': self.config.protected_paths,
                'block_config': {
                    'size': self.config.block_config.size,
                    'algorithm': self.config.block_config.algorithm
                },
                'ransomware_thresholds': {
                    'files_count': self.config.ransomware_thresholds.files_count,
                    'time_window': self.config.ransomware_thresholds.time_window,
                    'block_change_percent': self.config.ransomware_thresholds.block_change_percent,
                    'entropy_threshold': self.config.ransomware_thresholds.entropy_threshold
                },
                'monitoring': {
                    'fallback_interval': self.config.monitoring.fallback_interval,
                    'use_inotify': self.config.monitoring.use_inotify
                },
                'storage_path': self.config.storage_path,
                'log_path': self.config.log_path,
                'ipc_socket': self.config.ipc_socket
            }
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(config_data, f, default_flow_style=False, allow_unicode=True)
            
            return True
            
        except Exception as e:
            print(f"Ошибка сохранения конфигурации: {e}")
            return False
    
    def add_protected_path(self, path: str) -> bool:
        """Добавление пути в список защищаемых"""
        if path not in self.config.protected_paths:
            self.config.protected_paths.append(path)
            return self.save()
        return True
    
    def remove_protected_path(self, path: str) -> bool:
        """Удаление пути из списка защищаемых"""
        if path in self.config.protected_paths:
            self.config.protected_paths.remove(path)
            return self.save()
        return True
    
    def set_update_mode(self, enabled: bool):
        """Установка режима обновления эталона"""
        self.config.update_mode = enabled
    
    def is_update_mode(self) -> bool:
        """Проверка активности режима обновления"""
        return self.config.update_mode
    
    def get_config(self) -> SystemConfig:
        """Получение текущей конфигурации"""
        return self.config