# daemon/hash_storage.py

import sqlite3
import os
import json
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from datetime import datetime
from dataclasses import dataclass

@dataclass
class FileRecord:
    """Запись о файле в доверенном состоянии"""
    file_path: str
    file_size: int
    block_size: int
    blocks_count: int
    block_hashes: List[str]  # список хэшей блоков
    created_at: str
    updated_at: str
    is_trusted: bool = True
    backup_path: Optional[str] = None

class HashStorage:
    """
    Хранилище эталонных хэшей файлов
    
    Отвечает за:
    - хранение доверенного состояния файлов
    - управление хэшами блоков
    - метаданные файлов
    - связь с резервными копиями
    """
    
    def __init__(self, storage_path: str = "/var/lib/secure_fs_guard/storage/hashes.db"):
        self.storage_path = storage_path
        self.connection: Optional[sqlite3.Connection] = None
        self._ensure_storage_directory()
        self._init_database()
    
    def _ensure_storage_directory(self):
        """Создание директории хранилища с правильными правами"""
        storage_dir = os.path.dirname(self.storage_path)
        Path(storage_dir).mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # Установка прав доступа (только root)
        if os.path.exists(storage_dir):
            os.chmod(storage_dir, 0o700)
    
    def _init_database(self):
        """Инициализация структуры базы данных"""
        try:
            self.connection = sqlite3.connect(self.storage_path, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
            
            cursor = self.connection.cursor()
            
            # Таблица файлов
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT UNIQUE NOT NULL,
                    file_size INTEGER NOT NULL,
                    block_size INTEGER NOT NULL,
                    blocks_count INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    is_trusted INTEGER DEFAULT 1,
                    backup_path TEXT
                )
            """)
            
            # Таблица хэшей блоков
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS block_hashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id INTEGER NOT NULL,
                    block_index INTEGER NOT NULL,
                    hash_value TEXT NOT NULL,
                    FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                    UNIQUE(file_id, block_index)
                )
            """)
            
            # Индексы для ускорения поиска
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_file_path ON files(file_path)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_block_file_id ON block_hashes(file_id)
            """)
            
            self.connection.commit()
            
            # Установка прав доступа к БД (только root)
            if os.path.exists(self.storage_path):
                os.chmod(self.storage_path, 0o600)
                
        except sqlite3.Error as e:
            raise Exception(f"Ошибка инициализации базы данных: {e}")
    
    def add_file(self, file_path: str, file_size: int, block_size: int, 
                 block_hashes: List[str], backup_path: Optional[str] = None) -> bool:
        """
        Добавление файла в доверенное состояние
        
        Args:
            file_path: путь к файлу
            file_size: размер файла в байтах
            block_size: размер блока в байтах
            block_hashes: список хэшей блоков
            backup_path: путь к резервной копии
            
        Returns:
            True если добавление успешно
        """
        try:
            cursor = self.connection.cursor()
            now = datetime.now().isoformat()
            blocks_count = len(block_hashes)
            
            # Вставка записи о файле
            cursor.execute("""
                INSERT OR REPLACE INTO files 
                (file_path, file_size, block_size, blocks_count, created_at, updated_at, is_trusted, backup_path)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?)
            """, (file_path, file_size, block_size, blocks_count, now, now, backup_path))
            
            file_id = cursor.lastrowid
            
            # Удаление старых хэшей (если файл обновляется)
            cursor.execute("DELETE FROM block_hashes WHERE file_id = ?", (file_id,))
            
            # Вставка хэшей блоков
            for block_index, hash_value in enumerate(block_hashes):
                cursor.execute("""
                    INSERT INTO block_hashes (file_id, block_index, hash_value)
                    VALUES (?, ?, ?)
                """, (file_id, block_index, hash_value))
            
            self.connection.commit()
            return True
            
        except sqlite3.Error as e:
            self.connection.rollback()
            raise Exception(f"Ошибка добавления файла {file_path}: {e}")
    
    def get_file(self, file_path: str) -> Optional[FileRecord]:
        """
        Получение информации о файле
        
        Args:
            file_path: путь к файлу
            
        Returns:
            FileRecord или None если файл не найден
        """
        try:
            cursor = self.connection.cursor()
            
            # Получение информации о файле
            cursor.execute("""
                SELECT * FROM files WHERE file_path = ?
            """, (file_path,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            file_id = row['id']
            
            # Получение хэшей блоков
            cursor.execute("""
                SELECT hash_value FROM block_hashes 
                WHERE file_id = ? 
                ORDER BY block_index
            """, (file_id,))
            
            block_hashes = [r['hash_value'] for r in cursor.fetchall()]
            
            return FileRecord(
                file_path=row['file_path'],
                file_size=row['file_size'],
                block_size=row['block_size'],
                blocks_count=row['blocks_count'],
                block_hashes=block_hashes,
                created_at=row['created_at'],
                updated_at=row['updated_at'],
                is_trusted=bool(row['is_trusted']),
                backup_path=row['backup_path']
            )
            
        except sqlite3.Error as e:
            raise Exception(f"Ошибка получения файла {file_path}: {e}")
    
    def update_file(self, file_path: str, file_size: int, block_hashes: List[str], 
                    backup_path: Optional[str] = None) -> bool:
        """
        Обновление эталонного состояния файла
        
        Args:
            file_path: путь к файлу
            file_size: новый размер файла
            block_hashes: новые хэши блоков
            backup_path: новый путь к резервной копии
            
        Returns:
            True если обновление успешно
        """
        try:
            cursor = self.connection.cursor()
            
            # Получение file_id
            cursor.execute("SELECT id, block_size FROM files WHERE file_path = ?", (file_path,))
            row = cursor.fetchone()
            
            if not row:
                return False
            
            file_id = row['id']
            block_size = row['block_size']
            now = datetime.now().isoformat()
            blocks_count = len(block_hashes)
            
            # Обновление метаданных файла
            cursor.execute("""
                UPDATE files 
                SET file_size = ?, blocks_count = ?, updated_at = ?, backup_path = ?
                WHERE id = ?
            """, (file_size, blocks_count, now, backup_path, file_id))
            
            # Удаление старых хэшей
            cursor.execute("DELETE FROM block_hashes WHERE file_id = ?", (file_id,))
            
            # Вставка новых хэшей
            for block_index, hash_value in enumerate(block_hashes):
                cursor.execute("""
                    INSERT INTO block_hashes (file_id, block_index, hash_value)
                    VALUES (?, ?, ?)
                """, (file_id, block_index, hash_value))
            
            self.connection.commit()
            return True
            
        except sqlite3.Error as e:
            self.connection.rollback()
            raise Exception(f"Ошибка обновления файла {file_path}: {e}")
    
    def remove_file(self, file_path: str) -> bool:
        """
        Удаление файла из доверенного состояния
        
        Args:
            file_path: путь к файлу
            
        Returns:
            True если удаление успешно
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute("DELETE FROM files WHERE file_path = ?", (file_path,))
            self.connection.commit()
            return cursor.rowcount > 0
            
        except sqlite3.Error as e:
            self.connection.rollback()
            raise Exception(f"Ошибка удаления файла {file_path}: {e}")
    
    def file_exists(self, file_path: str) -> bool:
        """
        Проверка существования файла в хранилище
        
        Args:
            file_path: путь к файлу
            
        Returns:
            True если файл есть в хранилище
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT 1 FROM files WHERE file_path = ? LIMIT 1", (file_path,))
            return cursor.fetchone() is not None
            
        except sqlite3.Error as e:
            raise Exception(f"Ошибка проверки файла {file_path}: {e}")
    
    def get_all_files(self) -> List[str]:
        """
        Получение списка всех файлов в доверенном состоянии
        
        Returns:
            список путей к файлам
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT file_path FROM files ORDER BY file_path")
            return [row['file_path'] for row in cursor.fetchall()]
            
        except sqlite3.Error as e:
            raise Exception(f"Ошибка получения списка файлов: {e}")
    
    def get_files_count(self) -> int:
        """
        Получение количества файлов в доверенном состоянии
        
        Returns:
            количество файлов
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM files")
            return cursor.fetchone()['count']
            
        except sqlite3.Error as e:
            raise Exception(f"Ошибка подсчёта файлов: {e}")
    
    def set_trust_status(self, file_path: str, is_trusted: bool) -> bool:
        """
        Установка статуса доверия файла
        
        Args:
            file_path: путь к файлу
            is_trusted: статус доверия
            
        Returns:
            True если обновление успешно
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute("""
                UPDATE files SET is_trusted = ? WHERE file_path = ?
            """, (1 if is_trusted else 0, file_path))
            self.connection.commit()
            return cursor.rowcount > 0
            
        except sqlite3.Error as e:
            self.connection.rollback()
            raise Exception(f"Ошибка установки статуса доверия для {file_path}: {e}")
    
    def get_statistics(self) -> Dict[str, any]:
        """
        Получение статистики хранилища
        
        Returns:
            словарь со статистикой
        """
        try:
            cursor = self.connection.cursor()
            
            # Общее количество файлов
            cursor.execute("SELECT COUNT(*) as count FROM files")
            total_files = cursor.fetchone()['count']
            
            # Доверенные файлы
            cursor.execute("SELECT COUNT(*) as count FROM files WHERE is_trusted = 1")
            trusted_files = cursor.fetchone()['count']
            
            # Общий размер файлов
            cursor.execute("SELECT SUM(file_size) as total_size FROM files")
            total_size = cursor.fetchone()['total_size'] or 0
            
            # Общее количество блоков
            cursor.execute("SELECT SUM(blocks_count) as total_blocks FROM files")
            total_blocks = cursor.fetchone()['total_blocks'] or 0
            
            # Количество хэшей
            cursor.execute("SELECT COUNT(*) as count FROM block_hashes")
            total_hashes = cursor.fetchone()['count']
            
            return {
                'total_files': total_files,
                'trusted_files': trusted_files,
                'untrusted_files': total_files - trusted_files,
                'total_size_bytes': total_size,
                'total_blocks': total_blocks,
                'total_hashes': total_hashes,
                'db_size_bytes': os.path.getsize(self.storage_path) if os.path.exists(self.storage_path) else 0
            }
            
        except sqlite3.Error as e:
            raise Exception(f"Ошибка получения статистики: {e}")
    
    def clear_all(self) -> bool:
        """
        ОПАСНО: Полная очистка хранилища
        Используется только при переинициализации системы
        
        Returns:
            True если очистка успешна
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute("DELETE FROM block_hashes")
            cursor.execute("DELETE FROM files")
            self.connection.commit()
            return True
            
        except sqlite3.Error as e:
            self.connection.rollback()
            raise Exception(f"Ошибка очистки хранилища: {e}")
    
    def verify_integrity(self) -> Tuple[bool, str]:
        """
        Проверка целостности самой базы данных
        
        Returns:
            (успешность, сообщение)
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute("PRAGMA integrity_check")
            result = cursor.fetchone()[0]
            
            if result == "ok":
                return True, "Целостность базы данных подтверждена"
            else:
                return False, f"Обнаружены проблемы: {result}"
                
        except sqlite3.Error as e:
            return False, f"Ошибка проверки целостности: {e}"
    
    def close(self):
        """Закрытие соединения с базой данных"""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def __enter__(self):
        """Поддержка контекстного менеджера"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Автоматическое закрытие при выходе из контекста"""
        self.close()