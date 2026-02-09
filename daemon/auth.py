# daemon/auth.py

import os
import time
import hashlib
import secrets
from typing import Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum

class SystemMode(Enum):
    """Режимы работы системы"""
    MONITOR = "MONITOR"           # Режим контроля (основной)
    INIT = "INIT"                 # Режим инициализации эталонного состояния
    UPDATE = "UPDATE"             # Режим обновления эталона
    EMERGENCY = "EMERGENCY"       # Аварийный режим

class AuthResult(Enum):
    """Результаты аутентификации/авторизации"""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    UNAUTHORIZED = "UNAUTHORIZED"

class AuthManager:
    """
    Менеджер аутентификации и авторизации
    
    Отвечает за:
    - управление режимами работы системы
    - контроль доверенных действий администратора
    - защиту от подмены эталонного состояния
    - временные ограничения для режимов
    """
    
    def __init__(self):
        self.current_mode = SystemMode.MONITOR
        self.mode_start_time: Optional[datetime] = None
        self.mode_timeout: Optional[int] = None  # секунды
        
        # Токены для сессий
        self.active_sessions: dict = {}  # {session_id: {user, created, expires}}
        
        # История режимов
        self.mode_history: list = []
        
        # Флаг аварийного режима
        self.emergency_triggered = False
        self.emergency_reason = ""
    
    def get_current_mode(self) -> SystemMode:
        """Получение текущего режима работы"""
        # Проверка истечения режима обновления
        if self.current_mode == SystemMode.UPDATE:
            if self._is_mode_expired():
                self._exit_update_mode()
        
        return self.current_mode
    
    def is_monitor_mode(self) -> bool:
        """Проверка режима контроля"""
        return self.get_current_mode() == SystemMode.MONITOR
    
    def is_update_mode(self) -> bool:
        """Проверка режима обновления"""
        return self.get_current_mode() == SystemMode.UPDATE
    
    def is_init_mode(self) -> bool:
        """Проверка режима инициализации"""
        return self.get_current_mode() == SystemMode.INIT
    
    def is_emergency_mode(self) -> bool:
        """Проверка аварийного режима"""
        return self.get_current_mode() == SystemMode.EMERGENCY
    
    def enter_init_mode(self, admin_user: str = "root") -> Tuple[bool, str]:
        """
        Вход в режим инициализации эталонного состояния
        
        Args:
            admin_user: имя администратора
            
        Returns:
            (успешность, сообщение)
        """
        if self.current_mode != SystemMode.MONITOR:
            return False, f"Невозможно войти в режим инициализации из режима {self.current_mode.value}"
        
        # Запись в историю
        self._record_mode_change(SystemMode.INIT, admin_user)
        
        self.current_mode = SystemMode.INIT
        self.mode_start_time = datetime.now()
        self.mode_timeout = None  # Нет автоматического выхода
        
        return True, "Режим инициализации включён"
    
    def exit_init_mode(self, admin_user: str = "root") -> Tuple[bool, str]:
        """
        Выход из режима инициализации
        
        Args:
            admin_user: имя администратора
            
        Returns:
            (успешность, сообщение)
        """
        if self.current_mode != SystemMode.INIT:
            return False, "Система не в режиме инициализации"
        
        # Запись в историю
        self._record_mode_change(SystemMode.MONITOR, admin_user)
        
        self.current_mode = SystemMode.MONITOR
        self.mode_start_time = None
        self.mode_timeout = None
        
        return True, "Режим инициализации завершён, система в режиме контроля"
    
    def enter_update_mode(self, admin_user: str = "root", 
                         timeout: int = 300) -> Tuple[bool, str, Optional[str]]:
        """
        Вход в режим обновления эталонного состояния
        
        Args:
            admin_user: имя администратора
            timeout: время в секундах (по умолчанию 5 минут)
            
        Returns:
            (успешность, сообщение, session_token)
        """
        if self.current_mode == SystemMode.EMERGENCY:
            return False, "Невозможно войти в режим обновления: система в аварийном режиме", None
        
        if self.current_mode == SystemMode.INIT:
            return False, "Невозможно войти в режим обновления: система в режиме инициализации", None
        
        if self.current_mode == SystemMode.UPDATE:
            # Уже в режиме обновления - продление сессии
            self.mode_timeout = timeout
            self.mode_start_time = datetime.now()
            return True, f"Режим обновления продлён на {timeout} секунд", None
        
        # Проверка прав (базовая)
        if not self._verify_admin(admin_user):
            return False, "Недостаточно прав для входа в режим обновления", None
        
        # Генерация токена сессии
        session_token = self._generate_session_token(admin_user, timeout)
        
        # Запись в историю
        self._record_mode_change(SystemMode.UPDATE, admin_user, timeout)
        
        self.current_mode = SystemMode.UPDATE
        self.mode_start_time = datetime.now()
        self.mode_timeout = timeout
        
        return True, f"Режим обновления включён на {timeout} секунд", session_token
    
    def exit_update_mode(self, admin_user: str = "root") -> Tuple[bool, str]:
        """
        Выход из режима обновления
        
        Args:
            admin_user: имя администратора
            
        Returns:
            (успешность, сообщение)
        """
        if self.current_mode != SystemMode.UPDATE:
            return False, "Система не в режиме обновления"
        
        return self._exit_update_mode(admin_user)
    
    def _exit_update_mode(self, admin_user: str = "auto") -> Tuple[bool, str]:
        """Внутренний метод выхода из режима обновления"""
        # Запись в историю
        self._record_mode_change(SystemMode.MONITOR, admin_user)
        
        self.current_mode = SystemMode.MONITOR
        self.mode_start_time = None
        self.mode_timeout = None
        
        # Очистка активных сессий
        self.active_sessions.clear()
        
        return True, "Режим обновления завершён, система в режиме контроля"
    
    def enter_emergency_mode(self, reason: str) -> Tuple[bool, str]:
        """
        Вход в аварийный режим
        
        Args:
            reason: причина активации
            
        Returns:
            (успешность, сообщение)
        """
        # Запись в историю
        self._record_mode_change(SystemMode.EMERGENCY, "system", reason=reason)
        
        # Принудительный выход из других режимов
        if self.current_mode == SystemMode.UPDATE:
            self._exit_update_mode("system")
        
        self.current_mode = SystemMode.EMERGENCY
        self.mode_start_time = datetime.now()
        self.mode_timeout = None
        self.emergency_triggered = True
        self.emergency_reason = reason
        
        return True, f"АВАРИЙНЫЙ РЕЖИМ АКТИВИРОВАН: {reason}"
    
    def exit_emergency_mode(self, admin_user: str = "root") -> Tuple[bool, str]:
        """
        Выход из аварийного режима (только вручную)
        
        Args:
            admin_user: имя администратора
            
        Returns:
            (успешность, сообщение)
        """
        if self.current_mode != SystemMode.EMERGENCY:
            return False, "Система не в аварийном режиме"
        
        # Проверка прав
        if not self._verify_admin(admin_user):
            return False, "Недостаточно прав для выхода из аварийного режима"
        
        # Запись в историю
        self._record_mode_change(SystemMode.MONITOR, admin_user)
        
        self.current_mode = SystemMode.MONITOR
        self.mode_start_time = None
        self.mode_timeout = None
        self.emergency_triggered = False
        self.emergency_reason = ""
        
        return True, "Аварийный режим деактивирован, система в режиме контроля"
    
    def _is_mode_expired(self) -> bool:
        """Проверка истечения времени режима"""
        if self.mode_timeout is None or self.mode_start_time is None:
            return False
        
        elapsed = (datetime.now() - self.mode_start_time).total_seconds()
        return elapsed > self.mode_timeout
    
    def get_mode_remaining_time(self) -> Optional[int]:
        """
        Получение оставшегося времени режима
        
        Returns:
            оставшиеся секунды или None
        """
        if self.mode_timeout is None or self.mode_start_time is None:
            return None
        
        elapsed = (datetime.now() - self.mode_start_time).total_seconds()
        remaining = self.mode_timeout - elapsed
        
        return max(0, int(remaining))
    
    def _verify_admin(self, admin_user: str) -> bool:
        """
        Базовая проверка прав администратора
        
        Args:
            admin_user: имя пользователя
            
        Returns:
            True если пользователь имеет права
        """
        # Проверка что процесс запущен под root
        if os.geteuid() != 0:
            return False
        
        # Базовая проверка - разрешаем root
        # В реальной системе здесь может быть более сложная логика
        return admin_user in ['root', 'admin']
    
    def _generate_session_token(self, admin_user: str, timeout: int) -> str:
        """
        Генерация токена сессии
        
        Args:
            admin_user: имя пользователя
            timeout: время жизни в секундах
            
        Returns:
            токен сессии
        """
        # Генерация случайного токена
        token = secrets.token_hex(32)
        
        # Сохранение сессии
        self.active_sessions[token] = {
            'user': admin_user,
            'created': datetime.now(),
            'expires': datetime.now() + timedelta(seconds=timeout)
        }
        
        return token
    
    def verify_session_token(self, token: str) -> AuthResult:
        """
        Проверка токена сессии
        
        Args:
            token: токен для проверки
            
        Returns:
            результат проверки
        """
        if token not in self.active_sessions:
            return AuthResult.UNAUTHORIZED
        
        session = self.active_sessions[token]
        
        if datetime.now() > session['expires']:
            # Удаление истёкшей сессии
            del self.active_sessions[token]
            return AuthResult.EXPIRED
        
        return AuthResult.SUCCESS
    
    def revoke_session(self, token: str) -> bool:
        """
        Отзыв токена сессии
        
        Args:
            token: токен для отзыва
            
        Returns:
            True если токен был отозван
        """
        if token in self.active_sessions:
            del self.active_sessions[token]
            return True
        return False
    
    def _record_mode_change(self, new_mode: SystemMode, admin_user: str, 
                           timeout: Optional[int] = None, reason: str = ""):
        """
        Запись изменения режима в историю
        
        Args:
            new_mode: новый режим
            admin_user: администратор
            timeout: время (для режима обновления)
            reason: причина (для аварийного режима)
        """
        record = {
            'timestamp': datetime.now().isoformat(),
            'from_mode': self.current_mode.value if self.current_mode else None,
            'to_mode': new_mode.value,
            'admin_user': admin_user,
            'timeout': timeout,
            'reason': reason
        }
        
        self.mode_history.append(record)
        
        # Ограничение размера истории
        if len(self.mode_history) > 1000:
            self.mode_history = self.mode_history[-1000:]
    
    def get_mode_history(self, limit: int = 50) -> list:
        """
        Получение истории изменения режимов
        
        Args:
            limit: количество записей
            
        Returns:
            список записей истории
        """
        return self.mode_history[-limit:]
    
    def get_status(self) -> dict:
        """
        Получение полного статуса системы авторизации
        
        Returns:
            словарь со статусом
        """
        status = {
            'current_mode': self.current_mode.value,
            'mode_start_time': self.mode_start_time.isoformat() if self.mode_start_time else None,
            'mode_timeout': self.mode_timeout,
            'remaining_time': self.get_mode_remaining_time(),
            'is_expired': self._is_mode_expired() if self.mode_timeout else False,
            'active_sessions_count': len(self.active_sessions),
            'emergency_triggered': self.emergency_triggered,
            'emergency_reason': self.emergency_reason if self.emergency_triggered else None
        }
        
        return status
    
    def validate_action(self, action: str, admin_user: str = "root") -> Tuple[bool, str]:
        """
        Валидация действия в текущем режиме
        
        Args:
            action: действие для проверки
            admin_user: пользователь
            
        Returns:
            (разрешено, сообщение)
        """
        mode = self.get_current_mode()
        
        # Действия, разрешённые в любом режиме
        always_allowed = ['get_status', 'view_logs', 'get_statistics']
        if action in always_allowed:
            return True, "Действие разрешено"
        
        # Режим контроля - только чтение
        if mode == SystemMode.MONITOR:
            read_actions = ['check_integrity', 'list_files', 'get_file_info']
            if action in read_actions:
                return True, "Действие разрешено в режиме контроля"
            else:
                return False, "Действие требует режима обновления или инициализации"
        
        # Режим инициализации - создание эталона
        if mode == SystemMode.INIT:
            init_actions = ['add_file', 'create_backup', 'initialize_baseline']
            if action in init_actions:
                return True, "Действие разрешено в режиме инициализации"
            else:
                return False, f"Действие '{action}' не разрешено в режиме инициализации"
        
        # Режим обновления - обновление эталона
        if mode == SystemMode.UPDATE:
            update_actions = ['update_file', 'modify_file', 'update_hashes', 'create_backup']
            if action in update_actions:
                return True, "Действие разрешено в режиме обновления"
            else:
                return False, f"Действие '{action}' не разрешено в режиме обновления"
        
        # Аварийный режим - только административные действия
        if mode == SystemMode.EMERGENCY:
            emergency_actions = ['restore_file', 'block_file', 'exit_emergency_mode']
            if action in emergency_actions:
                if self._verify_admin(admin_user):
                    return True, "Действие разрешено в аварийном режиме"
                else:
                    return False, "Недостаточно прав в аварийном режиме"
            else:
                return False, "В аварийном режиме доступны только восстановление и выход"
        
        return False, "Неизвестное действие или режим"
    
    def cleanup_expired_sessions(self):
        """Очистка истёкших сессий"""
        now = datetime.now()
        expired = [
            token for token, session in self.active_sessions.items()
            if now > session['expires']
        ]
        
        for token in expired:
            del self.active_sessions[token]
        
        return len(expired)