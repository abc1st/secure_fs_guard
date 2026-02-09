# daemon/recovery.py

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple, List
from enum import Enum
from datetime import datetime
import stat

class RecoveryMethod(Enum):
    """Методы восстановления файла"""
    BACKUP_FULL = "BACKUP_FULL"           # Полное восстановление из резервной копии
    BACKUP_BLOCKS = "BACKUP_BLOCKS"       # Поблочное восстановление
    ROLLBACK = "ROLLBACK"                 # Откат изменений
    NONE = "NONE"                         # Восстановление невозможно

class RecoveryAction(Enum):
    """Действия противодействия"""
    RESTORE = "RESTORE"                   # Восстановление файла
    BLOCK = "BLOCK"                       # Блокировка файла
    TERMINATE_PROCESS = "TERMINATE_PROCESS"  # Завершение процесса
    QUARANTINE = "QUARANTINE"             # Помещение в карантин

class RecoveryResult:
    """Результат операции восстановления"""
    def __init__(self, success: bool, method: RecoveryMethod, message: str, 
                 restored_blocks: int = 0, process_terminated: bool = False):
        self.success = success
        self.method = method
        self.message = message
        self.restored_blocks = restored_blocks
        self.process_terminated = process_terminated
        self.timestamp = datetime.now().isoformat()

class RecoveryEngine:
    """
    Движок активного противодействия
    
    Отвечает за:
    - восстановление файлов из резервных копий
    - поблочное восстановление
    - блокировку файлов
    - завершение вредоносных процессов
    - карантин
    """
    
    def __init__(self, backup_dir: str = "/var/lib/secure_fs_guard/storage/backups",
                 quarantine_dir: str = "/var/lib/secure_fs_guard/quarantine",
                 block_size: int = 65536):
        """
        Args:
            backup_dir: директория резервных копий
            quarantine_dir: директория карантина
            block_size: размер блока в байтах
        """
        self.backup_dir = backup_dir
        self.quarantine_dir = quarantine_dir
        self.block_size = block_size
        
        self._ensure_directories()
    
    def _ensure_directories(self):
        """Создание необходимых директорий"""
        for directory in [self.backup_dir, self.quarantine_dir]:
            Path(directory).mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(directory, 0o700)
    
    def create_backup(self, file_path: str) -> Tuple[bool, str]:
        """
        Создание резервной копии файла
        
        Args:
            file_path: путь к файлу
            
        Returns:
            (успешность, путь к резервной копии или сообщение об ошибке)
        """
        if not os.path.exists(file_path):
            return False, f"Файл не существует: {file_path}"
        
        if not os.path.isfile(file_path):
            return False, f"Путь не является файлом: {file_path}"
        
        try:
            # Формирование имени резервной копии
            backup_name = self._generate_backup_name(file_path)
            backup_path = os.path.join(self.backup_dir, backup_name)
            
            # Создание поддиректорий в backup_dir если нужно
            backup_subdir = os.path.dirname(backup_path)
            if backup_subdir:
                Path(backup_subdir).mkdir(parents=True, exist_ok=True, mode=0o700)
            
            # Копирование файла
            shutil.copy2(file_path, backup_path)
            
            # Установка прав доступа
            os.chmod(backup_path, 0o600)
            
            return True, backup_path
        
        except PermissionError:
            return False, f"Нет прав доступа к {file_path}"
        except Exception as e:
            return False, f"Ошибка создания резервной копии: {e}"
    
    def _generate_backup_name(self, file_path: str) -> str:
        """
        Генерация имени резервной копии
        
        Args:
            file_path: оригинальный путь к файлу
            
        Returns:
            имя резервной копии
        """
        # Замена слэшей на подчёркивания
        safe_path = file_path.replace('/', '_').replace(os.sep, '_')
        
        # Добавление временной метки
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        return f"{safe_path}_{timestamp}.backup"
    
    def restore_from_backup(self, file_path: str, backup_path: str) -> RecoveryResult:
        """
        Полное восстановление файла из резервной копии
        
        Args:
            file_path: путь к восстанавливаемому файлу
            backup_path: путь к резервной копии
            
        Returns:
            результат восстановления
        """
        if not os.path.exists(backup_path):
            return RecoveryResult(
                success=False,
                method=RecoveryMethod.BACKUP_FULL,
                message=f"Резервная копия не найдена: {backup_path}"
            )
        
        try:
            # Создание директории для файла если нужно
            file_dir = os.path.dirname(file_path)
            if file_dir:
                Path(file_dir).mkdir(parents=True, exist_ok=True)
            
            # Временная блокировка файла (попытка)
            self._lock_file(file_path)
            
            # Копирование резервной копии
            shutil.copy2(backup_path, file_path)
            
            # Восстановление прав доступа (базовые)
            os.chmod(file_path, 0o644)
            
            # Разблокировка файла
            self._unlock_file(file_path)
            
            return RecoveryResult(
                success=True,
                method=RecoveryMethod.BACKUP_FULL,
                message=f"Файл успешно восстановлен из резервной копии"
            )
        
        except PermissionError:
            return RecoveryResult(
                success=False,
                method=RecoveryMethod.BACKUP_FULL,
                message=f"Нет прав доступа для восстановления {file_path}"
            )
        except Exception as e:
            return RecoveryResult(
                success=False,
                method=RecoveryMethod.BACKUP_FULL,
                message=f"Ошибка восстановления: {e}"
            )
    
    def restore_blocks(self, file_path: str, backup_path: str, 
                      block_indices: List[int]) -> RecoveryResult:
        """
        Поблочное восстановление файла
        
        Args:
            file_path: путь к файлу
            backup_path: путь к резервной копии
            block_indices: индексы блоков для восстановления
            
        Returns:
            результат восстановления
        """
        if not os.path.exists(backup_path):
            return RecoveryResult(
                success=False,
                method=RecoveryMethod.BACKUP_BLOCKS,
                message=f"Резервная копия не найдена: {backup_path}"
            )
        
        if not os.path.exists(file_path):
            # Если файл не существует, делаем полное восстановление
            return self.restore_from_backup(file_path, backup_path)
        
        try:
            # Временная блокировка
            self._lock_file(file_path)
            
            restored_count = 0
            
            backup_size = os.path.getsize(backup_path)
            
            # Открытие обоих файлов
            with open(backup_path, 'rb') as backup_file, \
                 open(file_path, 'r+b') as target_file:
                
                for block_index in sorted(block_indices):
                    # Позиция блока
                    block_offset = block_index * self.block_size
                    
                    # Чтение блока из резервной копии
                    backup_file.seek(block_offset)
                    block_data = backup_file.read(self.block_size)
                    
                    if not block_data:
                        # Блок за пределами файла
                        continue
                    
                    # Запись блока в целевой файл
                    target_file.seek(block_offset)
                    target_file.write(block_data)
                    
                    restored_count += 1
                    
                # Удаляем лишние данные, если файл увеличился после изменений
                target_file.truncate(backup_size)
            
            # Разблокировка
            self._unlock_file(file_path)
            
            return RecoveryResult(
                success=True,
                method=RecoveryMethod.BACKUP_BLOCKS,
                message=f"Восстановлено блоков: {restored_count}/{len(block_indices)}",
                restored_blocks=restored_count
            )
        
        except Exception as e:
            return RecoveryResult(
                success=False,
                method=RecoveryMethod.BACKUP_BLOCKS,
                message=f"Ошибка поблочного восстановления: {e}"
            )
    
    def block_file(self, file_path: str, permanent: bool = False) -> Tuple[bool, str]:
        """
        Блокировка файла от изменений
        
        Args:
            file_path: путь к файлу
            permanent: постоянная блокировка (иначе временная)
            
        Returns:
            (успешность, сообщение)
        """
        if not os.path.exists(file_path):
            return False, f"Файл не существует: {file_path}"
        
        try:
            # Метод 1: chmod (убираем права на запись)
            current_mode = os.stat(file_path).st_mode
            os.chmod(file_path, current_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
            
            # Метод 2: chattr +i (immutable) - только если постоянная блокировка
            if permanent:
                try:
                    subprocess.run(
                        ['chattr', '+i', file_path],
                        check=True,
                        capture_output=True,
                        timeout=5
                    )
                    return True, f"Файл заблокирован (постоянно)"
                except (subprocess.CalledProcessError, FileNotFoundError):
                    # chattr может быть недоступен
                    return True, f"Файл заблокирован (chmod)"
            
            return True, f"Файл заблокирован (временно)"
        
        except PermissionError:
            return False, f"Нет прав для блокировки {file_path}"
        except Exception as e:
            return False, f"Ошибка блокировки: {e}"
    
    def unblock_file(self, file_path: str) -> Tuple[bool, str]:
        """
        Разблокировка файла
        
        Args:
            file_path: путь к файлу
            
        Returns:
            (успешность, сообщение)
        """
        if not os.path.exists(file_path):
            return False, f"Файл не существует: {file_path}"
        
        try:
            # Снятие immutable флага
            try:
                subprocess.run(
                    ['chattr', '-i', file_path],
                    check=True,
                    capture_output=True,
                    timeout=5
                )
            except (subprocess.CalledProcessError, FileNotFoundError):
                # chattr может быть недоступен
                pass
            
            # Восстановление прав на запись
            current_mode = os.stat(file_path).st_mode
            os.chmod(file_path, current_mode | stat.S_IWUSR)
            
            return True, f"Файл разблокирован"
        
        except Exception as e:
            return False, f"Ошибка разблокировки: {e}"
    
    def _lock_file(self, file_path: str):
        """Временная блокировка файла на время операции"""
        try:
            if os.path.exists(file_path):
                current_mode = os.stat(file_path).st_mode
                os.chmod(file_path, current_mode & ~stat.S_IWUSR & ~stat.S_IWGRP & ~stat.S_IWOTH)
        except:
            pass
    
    def _unlock_file(self, file_path: str):
        """Разблокировка файла после операции"""
        try:
            if os.path.exists(file_path):
                current_mode = os.stat(file_path).st_mode
                os.chmod(file_path, current_mode | stat.S_IWUSR)
        except:
            pass
    
    def find_process_accessing_file(self, file_path: str) -> List[Tuple[int, str]]:
        """
        Поиск процессов, работающих с файлом
        
        Args:
            file_path: путь к файлу
            
        Returns:
            список (pid, имя_процесса)
        """
        processes = []
        
        try:
            # Использование lsof для поиска процессов
            result = subprocess.run(
                ['lsof', '-t', file_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0 and result.stdout.strip():
                pids = result.stdout.strip().split('\n')
                
                for pid in pids:
                    try:
                        pid = int(pid.strip())
                        
                        # Получение имени процесса
                        with open(f'/proc/{pid}/comm', 'r') as f:
                            process_name = f.read().strip()
                        
                        processes.append((pid, process_name))
                    except:
                        continue
        
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # lsof может быть недоступен
            pass
        
        return processes
    
    def terminate_process(self, pid: int, force: bool = False) -> Tuple[bool, str]:
        """
        Завершение процесса
        
        Args:
            pid: ID процесса
            force: принудительное завершение (SIGKILL)
            
        Returns:
            (успешность, сообщение)
        """
        try:
            # Проверка существования процесса
            if not os.path.exists(f'/proc/{pid}'):
                return False, f"Процесс {pid} не существует"
            
            # Получение имени процесса
            try:
                with open(f'/proc/{pid}/comm', 'r') as f:
                    process_name = f.read().strip()
            except:
                process_name = "unknown"
            
            # Завершение процесса
            signal = 'SIGKILL' if force else 'SIGTERM'
            
            subprocess.run(
                ['kill', '-9' if force else '-15', str(pid)],
                check=True,
                timeout=5
            )
            
            return True, f"Процесс {pid} ({process_name}) завершён ({signal})"
        
        except subprocess.CalledProcessError:
            return False, f"Не удалось завершить процесс {pid}"
        except Exception as e:
            return False, f"Ошибка завершения процесса: {e}"
    
    def quarantine_file(self, file_path: str) -> Tuple[bool, str]:
        """
        Помещение файла в карантин
        
        Args:
            file_path: путь к файлу
            
        Returns:
            (успешность, путь в карантине или сообщение об ошибке)
        """
        if not os.path.exists(file_path):
            return False, f"Файл не существует: {file_path}"
        
        try:
            # Генерация имени в карантине
            quarantine_name = self._generate_backup_name(file_path)
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            
            # Перемещение в карантин
            shutil.move(file_path, quarantine_path)
            
            # Блокировка файла в карантине
            os.chmod(quarantine_path, 0o000)
            
            return True, quarantine_path
        
        except Exception as e:
            return False, f"Ошибка помещения в карантин: {e}"
    
    def restore_from_quarantine(self, quarantine_path: str, original_path: str) -> Tuple[bool, str]:
        """
        Восстановление файла из карантина
        
        Args:
            quarantine_path: путь к файлу в карантине
            original_path: оригинальный путь
            
        Returns:
            (успешность, сообщение)
        """
        if not os.path.exists(quarantine_path):
            return False, f"Файл не найден в карантине: {quarantine_path}"
        
        try:
            # Восстановление прав
            os.chmod(quarantine_path, 0o644)
            
            # Создание директории если нужно
            file_dir = os.path.dirname(original_path)
            if file_dir:
                Path(file_dir).mkdir(parents=True, exist_ok=True)
            
            # Перемещение обратно
            shutil.move(quarantine_path, original_path)
            
            return True, f"Файл восстановлен из карантина"
        
        except Exception as e:
            return False, f"Ошибка восстановления из карантина: {e}"
    
    def emergency_block_all(self, file_paths: List[str]) -> Tuple[int, int]:
        """
        Аварийная блокировка множества файлов (при обнаружении ransomware)
        
        Args:
            file_paths: список путей к файлам
            
        Returns:
            (количество заблокированных, количество ошибок)
        """
        blocked = 0
        errors = 0
        
        for file_path in file_paths:
            success, _ = self.block_file(file_path, permanent=True)
            if success:
                blocked += 1
            else:
                errors += 1
        
        return blocked, errors
    
    def get_backup_info(self, file_path: str) -> Optional[dict]:
        """
        Получение информации о резервной копии файла
        
        Args:
            file_path: путь к оригинальному файлу
            
        Returns:
            информация о последней резервной копии или None
        """
        # Поиск всех резервных копий этого файла
        safe_path = file_path.replace('/', '_').replace(os.sep, '_')
        
        backups = []
        for backup_file in os.listdir(self.backup_dir):
            if backup_file.startswith(safe_path):
                backup_path = os.path.join(self.backup_dir, backup_file)
                stat_info = os.stat(backup_path)
                backups.append({
                    'path': backup_path,
                    'size': stat_info.st_size,
                    'created': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
                    'modified': datetime.fromtimestamp(stat_info.st_mtime).isoformat()
                })
        
        if not backups:
            return None
        
        # Возврат последней резервной копии
        return max(backups, key=lambda x: x['created'])