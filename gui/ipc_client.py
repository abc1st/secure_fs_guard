# gui/ipc_client.py

import json
import socket
import struct
from typing import Tuple, Optional, Any
from enum import Enum

class IPCCommand(Enum):
    """Команды IPC (дублирование из daemon)"""
    # Статус системы
    GET_STATUS = "get_status"
    GET_STATISTICS = "get_statistics"
    GET_LOGS = "get_logs"
    
    # Управление режимами
    ENTER_INIT_MODE = "enter_init_mode"
    EXIT_INIT_MODE = "exit_init_mode"
    ENTER_UPDATE_MODE = "enter_update_mode"
    EXIT_UPDATE_MODE = "exit_update_mode"
    EXIT_EMERGENCY_MODE = "exit_emergency_mode"
    
    # Управление путями
    ADD_PATH = "add_path"
    REMOVE_PATH = "remove_path"
    GET_PATHS = "get_paths"
    
    # Управление файлами
    GET_FILES = "get_files"
    GET_FILE_INFO = "get_file_info"
    CHECK_FILE = "check_file"
    RESTORE_FILE = "restore_file"
    
    # Управление мониторингом
    START_MONITORING = "start_monitoring"
    STOP_MONITORING = "stop_monitoring"
    PAUSE_MONITORING = "pause_monitoring"
    RESUME_MONITORING = "resume_monitoring"
    
    # Инициализация
    INITIALIZE_BASELINE = "initialize_baseline"
    
    # Конфигурация
    GET_CONFIG = "get_config"
    UPDATE_CONFIG = "update_config"
    
    # Система
    SHUTDOWN = "shutdown"
    PING = "ping"

class DaemonClient:
    """
    Клиент для связи с демоном
    
    Используется GUI для отправки команд и получения данных
    """
    
    IPCCommand = IPCCommand
    def __init__(self, socket_path: str = "/var/run/secure_fs_guard.sock"):
        """
        Args:
            socket_path: путь к UNIX socket демона
        """
        self.socket_path = socket_path
        self.client_socket: Optional[socket.socket] = None
        self.is_connected = False
    
    def connect(self) -> Tuple[bool, str]:
        """
        Подключение к демону
        
        Returns:
            (успешность, сообщение)
        """
        if self.is_connected:
            return True, "Уже подключён"
        
        try:
            self.client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.client_socket.settimeout(5.0)  # Таймаут 5 секунд
            self.client_socket.connect(self.socket_path)
            self.is_connected = True
            return True, "Подключение установлено"
        
        except FileNotFoundError:
            return False, f"Демон не запущен (socket не найден: {self.socket_path})"
        except ConnectionRefusedError:
            return False, "Демон не отвечает"
        except socket.timeout:
            return False, "Таймаут подключения"
        except PermissionError:
            return False, "Нет прав доступа к socket"
        except Exception as e:
            return False, f"Ошибка подключения: {e}"
    
    def disconnect(self):
        """Отключение от демона"""
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            self.client_socket = None
        self.is_connected = False
    
    def send_command(self, command: IPCCommand, params: dict = None) -> Tuple[bool, Any, str]:
        """
        Отправка команды демону
        
        Args:
            command: команда
            params: параметры команды
            
        Returns:
            (успешность, данные, ошибка)
        """
        if not self.is_connected:
            return False, None, "Не подключён к демону"
        
        try:
            # Формирование сообщения
            message = {
                'command': command.value,
                'params': params or {}
            }
            
            message_json = json.dumps(message)
            message_bytes = message_json.encode('utf-8')
            
            # Отправка длины + данных
            length = struct.pack('!I', len(message_bytes))
            self.client_socket.sendall(length + message_bytes)
            
            # Получение ответа
            # Чтение длины
            length_data = self._recv_exact(4)
            if not length_data:
                self.is_connected = False
                return False, None, "Соединение разорвано"
            
            response_length = struct.unpack('!I', length_data)[0]
            
            # Чтение данных
            response_data = self._recv_exact(response_length)
            if not response_data:
                self.is_connected = False
                return False, None, "Соединение разорвано"
            
            # Парсинг ответа
            response = json.loads(response_data.decode('utf-8'))
            
            return response['success'], response.get('data'), response.get('error', '')
        
        except socket.timeout:
            return False, None, "Таймаут ожидания ответа"
        except json.JSONDecodeError:
            return False, None, "Неверный формат ответа"
        except Exception as e:
            self.is_connected = False
            return False, None, f"Ошибка отправки команды: {e}"
    
    def _recv_exact(self, length: int) -> Optional[bytes]:
        """Чтение точного количества байт"""
        data = b''
        while len(data) < length:
            try:
                chunk = self.client_socket.recv(length - len(data))
                if not chunk:
                    return None
                data += chunk
            except socket.timeout:
                return None
        return data
    
    # ========== Удобные методы для команд ==========
    
    def get_status(self) -> Tuple[bool, dict, str]:
        """Получение статуса системы"""
        return self.send_command(IPCCommand.GET_STATUS)
    
    def get_statistics(self) -> Tuple[bool, dict, str]:
        """Получение статистики"""
        return self.send_command(IPCCommand.GET_STATISTICS)
    
    def get_logs(self, lines: int = 100) -> Tuple[bool, list, str]:
        """Получение логов"""
        success, data, error = self.send_command(IPCCommand.GET_LOGS, {'lines': lines})
        if success and data:
            return True, data.get('logs', []), ""
        return False, [], error
    
    def enter_init_mode(self, admin_user: str = "gui") -> Tuple[bool, str, str]:
        """Вход в режим инициализации"""
        success, data, error = self.send_command(IPCCommand.ENTER_INIT_MODE, {'admin_user': admin_user})
        if success and data:
            return True, data.get('message', ''), ""
        return False, "", error
    
    def exit_init_mode(self, admin_user: str = "gui") -> Tuple[bool, str, str]:
        """Выход из режима инициализации"""
        success, data, error = self.send_command(IPCCommand.EXIT_INIT_MODE, {'admin_user': admin_user})
        if success and data:
            return True, data.get('message', ''), ""
        return False, "", error
    
    def enter_update_mode(self, timeout: int = 300, admin_user: str = "gui") -> Tuple[bool, str, str]:
        """Вход в режим обновления"""
        success, data, error = self.send_command(IPCCommand.ENTER_UPDATE_MODE, {
            'admin_user': admin_user,
            'timeout': timeout
        })
        if success and data:
            return True, data.get('message', ''), ""
        return False, "", error
    
    def exit_update_mode(self, admin_user: str = "gui") -> Tuple[bool, str, str]:
        """Выход из режима обновления"""
        success, data, error = self.send_command(IPCCommand.EXIT_UPDATE_MODE, {'admin_user': admin_user})
        if success and data:
            return True, data.get('message', ''), ""
        return False, "", error
    
    def exit_emergency_mode(self, admin_user: str = "gui") -> Tuple[bool, str, str]:
        """Выход из аварийного режима"""
        success, data, error = self.send_command(IPCCommand.EXIT_EMERGENCY_MODE, {'admin_user': admin_user})
        if success and data:
            return True, data.get('message', ''), ""
        return False, "", error
    
    def add_path(self, path: str, admin_user: str = "gui") -> Tuple[bool, str, str]:
        """Добавление защищаемого пути"""
        success, data, error = self.send_command(IPCCommand.ADD_PATH, {
            'path': path,
            'admin_user': admin_user
        })
        if success and data:
            return True, data.get('message', ''), ""
        return False, "", error
    
    def remove_path(self, path: str, admin_user: str = "gui") -> Tuple[bool, str, str]:
        """Удаление защищаемого пути"""
        success, data, error = self.send_command(IPCCommand.REMOVE_PATH, {
            'path': path,
            'admin_user': admin_user
        })
        if success and data:
            return True, data.get('message', ''), ""
        return False, "", error
    
    def get_paths(self) -> Tuple[bool, list, str]:
        """Получение списка защищаемых путей"""
        success, data, error = self.send_command(IPCCommand.GET_PATHS)
        if success and data:
            return True, data.get('paths', []), ""
        return False, [], error
    
    def get_files(self) -> Tuple[bool, list, str]:
        """Получение списка файлов"""
        success, data, error = self.send_command(IPCCommand.GET_FILES)
        if success and data:
            return True, data.get('files', []), ""
        return False, [], error
    
    def get_file_info(self, file_path: str) -> Tuple[bool, dict, str]:
        """Получение информации о файле"""
        return self.send_command(IPCCommand.GET_FILE_INFO, {'file_path': file_path})
    
    def check_file(self, file_path: str) -> Tuple[bool, dict, str]:
        """Проверка целостности файла"""
        return self.send_command(IPCCommand.CHECK_FILE, {'file_path': file_path})
    
    def restore_file(self, file_path: str) -> Tuple[bool, str, str]:
        """Восстановление файла"""
        success, data, error = self.send_command(IPCCommand.RESTORE_FILE, {'file_path': file_path})
        if success and data:
            return True, data.get('message', ''), ""
        return False, "", error
    
    def initialize_baseline(self) -> Tuple[bool, str, str]:
        """Запуск инициализации эталонного состояния"""
        success, data, error = self.send_command(IPCCommand.INITIALIZE_BASELINE)
        if success and data:
            return True, data.get('message', ''), ""
        return False, "", error
    
    def get_config(self) -> Tuple[bool, dict, str]:
        """Получение конфигурации"""
        return self.send_command(IPCCommand.GET_CONFIG)
    
    def ping(self) -> bool:
        """Проверка связи с демоном"""
        success, data, error = self.send_command(IPCCommand.PING)
        return success
    
    def shutdown_daemon(self, admin_user: str = "gui") -> Tuple[bool, str, str]:
        """Остановка демона"""
        success, data, error = self.send_command(IPCCommand.SHUTDOWN, {'admin_user': admin_user})
        if success and data:
            return True, data.get('message', ''), ""
        return False, "", error
    
    def __enter__(self):
        """Контекстный менеджер - вход"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Контекстный менеджер - выход"""
        self.disconnect()