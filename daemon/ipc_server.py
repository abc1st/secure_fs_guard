# daemon/ipc_server.py

import os
import json
import socket
import threading
import struct
from pathlib import Path
from typing import Callable, Optional, Dict, Any, Tuple
from enum import Enum

class IPCCommand(Enum):
    """Команды IPC"""
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

class IPCResponse:
    """Ответ IPC сервера"""
    def __init__(self, success: bool, data: Any = None, error: str = ""):
        self.success = success
        self.data = data
        self.error = error
    
    def to_dict(self) -> dict:
        """Преобразование в словарь"""
        return {
            'success': self.success,
            'data': self.data,
            'error': self.error
        }
    
    def to_json(self) -> str:
        """Преобразование в JSON"""
        return json.dumps(self.to_dict())

class IPCServer:
    """
    Сервер межпроцессного взаимодействия
    
    Отвечает за:
    - приём команд от GUI
    - передачу команд в систему
    - отправку ответов и уведомлений
    """
    
    def __init__(self, socket_path: str = "/var/run/secure_fs_guard.sock"):
        """
        Args:
            socket_path: путь к UNIX socket
        """
        self.socket_path = socket_path
        self.server_socket: Optional[socket.socket] = None
        self.is_running = False
        self.accept_thread: Optional[threading.Thread] = None
        
        # Обработчики команд
        self.command_handlers: Dict[str, Callable] = {}
        
        # Активные клиентские соединения
        self.active_connections: list = []
        self.connections_lock = threading.Lock()
        
        # Callback для логирования
        self.log_callback: Optional[Callable] = None
    
    def set_log_callback(self, callback: Callable):
        """Установка callback для логирования"""
        self.log_callback = callback
    
    def _log(self, message: str):
        """Внутреннее логирование"""
        if self.log_callback:
            self.log_callback(message)
    
    def register_handler(self, command: IPCCommand, handler: Callable):
        """
        Регистрация обработчика команды
        
        Args:
            command: команда
            handler: функция-обработчик
        """
        self.command_handlers[command.value] = handler
    
    def start(self) -> bool:
        """
        Запуск IPC сервера
        
        Returns:
            True если запуск успешен
        """
        if self.is_running:
            return True
        
        try:
            # Удаление старого socket если существует
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
            
            # Создание директории для socket
            socket_dir = os.path.dirname(self.socket_path)
            Path(socket_dir).mkdir(parents=True, exist_ok=True, mode=0o755)
            
            # Создание UNIX socket
            self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.server_socket.bind(self.socket_path)
            self.server_socket.listen(5)
            
            # Установка прав доступа к socket
            os.chmod(self.socket_path, 0o666)  # Разрешаем подключение не-root пользователям
            
            self.is_running = True
            
            # Запуск потока приёма соединений
            self.accept_thread = threading.Thread(
                target=self._accept_connections,
                daemon=True,
                name="IPCAcceptThread"
            )
            self.accept_thread.start()
            
            self._log("IPC сервер запущен")
            return True
        
        except Exception as e:
            self._log(f"Ошибка запуска IPC сервера: {e}")
            return False
    
    def stop(self):
        """Остановка IPC сервера"""
        self.is_running = False
        
        # Закрытие всех активных соединений
        with self.connections_lock:
            for conn in self.active_connections:
                try:
                    conn.close()
                except:
                    pass
            self.active_connections.clear()
        
        # Закрытие серверного socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        # Удаление socket файла
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except:
                pass
        
        self._log("IPC сервер остановлен")
    
    def _accept_connections(self):
        """Поток приёма новых соединений"""
        while self.is_running:
            try:
                # Приём соединения
                client_socket, client_address = self.server_socket.accept()
                
                self._log(f"Новое подключение: {client_address}")
                
                # Добавление в список активных
                with self.connections_lock:
                    self.active_connections.append(client_socket)
                
                # Запуск потока обработки клиента
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket,),
                    daemon=True,
                    name=f"IPCClientThread-{len(self.active_connections)}"
                )
                client_thread.start()
            
            except Exception as e:
                if self.is_running:
                    self._log(f"Ошибка приёма соединения: {e}")
    
    def _handle_client(self, client_socket: socket.socket):
        """
        Обработка клиентского соединения
        
        Args:
            client_socket: сокет клиента
        """
        try:
            while self.is_running:
                # Чтение длины сообщения (4 байта)
                length_data = self._recv_exact(client_socket, 4)
                if not length_data:
                    break
                
                message_length = struct.unpack('!I', length_data)[0]
                
                # Защита от слишком больших сообщений
                if message_length > 10 * 1024 * 1024:  # 10 MB
                    self._log(f"Получено слишком большое сообщение: {message_length} байт")
                    break
                
                # Чтение данных сообщения
                message_data = self._recv_exact(client_socket, message_length)
                if not message_data:
                    break
                
                # Обработка сообщения
                try:
                    message = json.loads(message_data.decode('utf-8'))
                    response = self._process_message(message)
                    
                    # Отправка ответа
                    self._send_response(client_socket, response)
                
                except json.JSONDecodeError:
                    error_response = IPCResponse(
                        success=False,
                        error="Неверный формат JSON"
                    )
                    self._send_response(client_socket, error_response)
                
                except Exception as e:
                    error_response = IPCResponse(
                        success=False,
                        error=f"Ошибка обработки: {str(e)}"
                    )
                    self._send_response(client_socket, error_response)
        
        except Exception as e:
            self._log(f"Ошибка обработки клиента: {e}")
        
        finally:
            # Удаление из списка активных
            with self.connections_lock:
                if client_socket in self.active_connections:
                    self.active_connections.remove(client_socket)
            
            # Закрытие соединения
            try:
                client_socket.close()
            except:
                pass
            
            self._log("Клиент отключён")
    
    def _recv_exact(self, sock: socket.socket, length: int) -> Optional[bytes]:
        """
        Чтение точного количества байт из сокета
        
        Args:
            sock: сокет
            length: количество байт
            
        Returns:
            данные или None при ошибке
        """
        data = b''
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def _send_response(self, sock: socket.socket, response: IPCResponse):
        """
        Отправка ответа клиенту
        
        Args:
            sock: сокет
            response: ответ
        """
        try:
            # Сериализация ответа
            response_json = response.to_json()
            response_bytes = response_json.encode('utf-8')
            
            # Отправка длины + данных
            length = struct.pack('!I', len(response_bytes))
            sock.sendall(length + response_bytes)
        
        except Exception as e:
            self._log(f"Ошибка отправки ответа: {e}")
    
    def _process_message(self, message: dict) -> IPCResponse:
        """
        Обработка входящего сообщения
        
        Args:
            message: сообщение от клиента
            
        Returns:
            ответ сервера
        """
        # Проверка структуры сообщения
        if 'command' not in message:
            return IPCResponse(
                success=False,
                error="Отсутствует поле 'command'"
            )
        
        command = message['command']
        params = message.get('params', {})
        
        # Поиск обработчика команды
        if command not in self.command_handlers:
            return IPCResponse(
                success=False,
                error=f"Неизвестная команда: {command}"
            )
        
        # Вызов обработчика
        try:
            handler = self.command_handlers[command]
            result = handler(params)
            
            # Обработчик может вернуть:
            # 1. IPCResponse
            # 2. Tuple[bool, Any] -> (success, data)
            # 3. Dict -> data
            
            if isinstance(result, IPCResponse):
                return result
            elif isinstance(result, tuple) and len(result) == 2:
                success, data = result
                return IPCResponse(success=success, data=data)
            elif isinstance(result, dict):
                return IPCResponse(success=True, data=result)
            else:
                return IPCResponse(success=True, data=result)
        
        except Exception as e:
            self._log(f"Ошибка выполнения команды {command}: {e}")
            return IPCResponse(
                success=False,
                error=f"Ошибка выполнения: {str(e)}"
            )
    
    def broadcast_notification(self, notification_type: str, data: Any):
        """
        Отправка уведомления всем подключённым клиентам
        
        Args:
            notification_type: тип уведомления
            data: данные уведомления
        """
        notification = {
            'type': 'notification',
            'notification_type': notification_type,
            'data': data,
            'timestamp': str(threading.current_thread().ident)
        }
        
        response = IPCResponse(success=True, data=notification)
        
        with self.connections_lock:
            for client_socket in self.active_connections[:]:  # Копия списка
                try:
                    self._send_response(client_socket, response)
                except Exception as e:
                    # Удаление неактивного соединения
                    self._log(f"Ошибка отправки уведомления: {e}")
                    if client_socket in self.active_connections:
                        self.active_connections.remove(client_socket)
                    try:
                        client_socket.close()
                    except:
                        pass
    
    def get_statistics(self) -> dict:
        """
        Получение статистики IPC сервера
        
        Returns:
            статистика
        """
        with self.connections_lock:
            active_count = len(self.active_connections)
        
        return {
            'is_running': self.is_running,
            'socket_path': self.socket_path,
            'active_connections': active_count,
            'registered_commands': len(self.command_handlers),
            'commands': list(self.command_handlers.keys())
        }

class IPCClient:
    """
    Клиент IPC для подключения к демону
    (Используется в GUI)
    """
    
    def __init__(self, socket_path: str = "/var/run/secure_fs_guard.sock"):
        """
        Args:
            socket_path: путь к UNIX socket
        """
        self.socket_path = socket_path
        self.client_socket: Optional[socket.socket] = None
        self.is_connected = False
    
    def connect(self) -> Tuple[bool, str]:
        """
        Подключение к серверу
        
        Returns:
            (успешность, сообщение)
        """
        if self.is_connected:
            return True, "Уже подключён"
        
        try:
            self.client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.client_socket.connect(self.socket_path)
            self.is_connected = True
            return True, "Подключение установлено"
        
        except FileNotFoundError:
            return False, f"Socket не найден: {self.socket_path}"
        except ConnectionRefusedError:
            return False, "Сервер не отвечает"
        except Exception as e:
            return False, f"Ошибка подключения: {e}"
    
    def disconnect(self):
        """Отключение от сервера"""
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            self.client_socket = None
        self.is_connected = False
    
    def send_command(self, command: IPCCommand, params: dict = None) -> Tuple[bool, Any, str]:
        """
        Отправка команды серверу
        
        Args:
            command: команда
            params: параметры команды
            
        Returns:
            (успешность, данные, ошибка)
        """
        if not self.is_connected:
            return False, None, "Не подключён к серверу"
        
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
                return False, None, "Соединение разорвано"
            
            response_length = struct.unpack('!I', length_data)[0]
            
            # Чтение данных
            response_data = self._recv_exact(response_length)
            if not response_data:
                return False, None, "Соединение разорвано"
            
            # Парсинг ответа
            response = json.loads(response_data.decode('utf-8'))
            
            return response['success'], response.get('data'), response.get('error', '')
        
        except Exception as e:
            return False, None, f"Ошибка отправки команды: {e}"
    
    def _recv_exact(self, length: int) -> Optional[bytes]:
        """Чтение точного количества байт"""
        data = b''
        while len(data) < length:
            chunk = self.client_socket.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data
    
    def __enter__(self):
        """Контекстный менеджер - вход"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Контекстный менеджер - выход"""
        self.disconnect()