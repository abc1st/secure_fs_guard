# daemon/integrity_engine.py

import hashlib
import os
import math
from typing import List, Optional, Tuple, Dict
from enum import Enum
from dataclasses import dataclass
from collections import deque
from datetime import datetime, timedelta

class ChangeType(Enum):
    """Типы изменений файла"""
    NO_CHANGE = "NO_CHANGE"                    # Файл не изменён
    ALLOWED_CHANGE = "ALLOWED_CHANGE"          # Допустимое изменение (режим обновления)
    UNAUTHORIZED_CHANGE = "UNAUTHORIZED_CHANGE"  # Несанкционированное изменение
    SUSPICIOUS_CHANGE = "SUSPICIOUS_CHANGE"    # Подозрительное изменение
    CRITICAL_CHANGE = "CRITICAL_CHANGE"        # Критическое изменение (возможно шифрование)

@dataclass
class IntegrityCheckResult:
    """Результат проверки целостности файла"""
    file_path: str
    change_type: ChangeType
    blocks_total: int
    blocks_changed: int
    change_percent: float
    current_hashes: List[str]
    reference_hashes: List[str]
    changed_block_indices: List[int]
    entropy: float = 0.0
    message: str = ""

@dataclass
class ModificationEvent:
    """Событие модификации файла (для отслеживания ransomware)"""
    file_path: str
    timestamp: datetime
    blocks_changed: int
    blocks_total: int
    change_percent: float
    entropy: float

class IntegrityEngine:
    """
    Движок контроля целостности
    
    Отвечает за:
    - разбиение файлов на блоки
    - вычисление хэшей блоков (SHA-256)
    - сравнение с эталоном
    - определение типа изменения
    - обнаружение ransomware-паттернов
    """
    
    def __init__(self, block_size: int = 65536, ransomware_thresholds: dict = None):
        """
        Args:
            block_size: размер блока в байтах (по умолчанию 64 KB)
            ransomware_thresholds: пороги для определения ransomware
        """
        self.block_size = block_size
        self.hash_algorithm = 'sha256'
        
        # Пороги ransomware
        self.ransomware_thresholds = ransomware_thresholds or {
            'files_count': 10,
            'time_window': 10,
            'block_change_percent': 70,
            'entropy_threshold': 7.5
        }
        
        # История модификаций для обнаружения массовых атак
        self.modification_history: deque = deque(maxlen=1000)
    
    def compute_file_hashes(self, file_path: str) -> Tuple[List[str], int]:
        """
        Вычисление хэшей всех блоков файла
        
        Args:
            file_path: путь к файлу
            
        Returns:
            (список хэшей блоков, размер файла)
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Файл не найден: {file_path}")
        
        if not os.path.isfile(file_path):
            raise ValueError(f"Путь не является файлом: {file_path}")
        
        block_hashes = []
        file_size = os.path.getsize(file_path)
        
        try:
            with open(file_path, 'rb') as f:
                while True:
                    block = f.read(self.block_size)
                    if not block:
                        break
                    
                    # Вычисление хэша блока
                    hasher = hashlib.sha256()
                    hasher.update(block)
                    block_hash = hasher.hexdigest()
                    block_hashes.append(block_hash)
            
            return block_hashes, file_size
            
        except PermissionError:
            raise PermissionError(f"Нет прав доступа к файлу: {file_path}")
        except Exception as e:
            raise Exception(f"Ошибка чтения файла {file_path}: {e}")
    
    def compare_hashes(self, current_hashes: List[str], reference_hashes: List[str]) -> Tuple[List[int], float]:
        """
        Сравнение текущих и эталонных хэшей
        
        Args:
            current_hashes: текущие хэши блоков
            reference_hashes: эталонные хэши блоков
            
        Returns:
            (список индексов изменённых блоков, процент изменений)
        """
        changed_indices = []
        
        # Если количество блоков изменилось, файл точно модифицирован
        max_blocks = max(len(current_hashes), len(reference_hashes))
        min_blocks = min(len(current_hashes), len(reference_hashes))
        
        # Сравнение общих блоков
        for i in range(min_blocks):
            if current_hashes[i] != reference_hashes[i]:
                changed_indices.append(i)
        
        # Если размер файла изменился, добавляем индексы новых/удалённых блоков
        if len(current_hashes) != len(reference_hashes):
            for i in range(min_blocks, max_blocks):
                changed_indices.append(i)
        
        # Процент изменённых блоков
        change_percent = (len(changed_indices) / max_blocks * 100) if max_blocks > 0 else 0
        
        return changed_indices, change_percent
    
    def calculate_entropy(self, file_path: str, sample_size: int = 1048576) -> float:
        """
        Вычисление энтропии данных файла (для обнаружения шифрования)
        
        Args:
            file_path: путь к файлу
            sample_size: размер выборки в байтах (по умолчанию 1 MB)
            
        Returns:
            энтропия (0-8, где 8 - максимальная случайность)
        """
        if not os.path.exists(file_path):
            return 0.0
        
        try:
            file_size = os.path.getsize(file_path)
            read_size = min(sample_size, file_size)
            
            if read_size == 0:
                return 0.0
            
            # Чтение выборки данных
            with open(file_path, 'rb') as f:
                data = f.read(read_size)
            
            if not data:
                return 0.0
            
            # Подсчёт частоты байтов
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Вычисление энтропии Шеннона
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception as e:
            # В случае ошибки возвращаем 0
            return 0.0
    
    def check_integrity(self, file_path: str, reference_hashes: List[str], 
                       is_update_mode: bool = False) -> IntegrityCheckResult:
        """
        Проверка целостности файла
        
        Args:
            file_path: путь к файлу
            reference_hashes: эталонные хэши блоков
            is_update_mode: включён ли режим обновления
            
        Returns:
            результат проверки целостности
        """
        try:
            # Вычисление текущих хэшей
            current_hashes, file_size = self.compute_file_hashes(file_path)
            
            # Сравнение хэшей
            changed_indices, change_percent = self.compare_hashes(current_hashes, reference_hashes)
            
            blocks_total = len(current_hashes)
            blocks_changed = len(changed_indices)
            
            # Определение типа изменения
            if blocks_changed == 0:
                # Файл не изменён
                return IntegrityCheckResult(
                    file_path=file_path,
                    change_type=ChangeType.NO_CHANGE,
                    blocks_total=blocks_total,
                    blocks_changed=0,
                    change_percent=0.0,
                    current_hashes=current_hashes,
                    reference_hashes=reference_hashes,
                    changed_block_indices=[],
                    message="Целостность подтверждена"
                )
            
            # Если режим обновления включён - это допустимое изменение
            if is_update_mode:
                return IntegrityCheckResult(
                    file_path=file_path,
                    change_type=ChangeType.ALLOWED_CHANGE,
                    blocks_total=blocks_total,
                    blocks_changed=blocks_changed,
                    change_percent=change_percent,
                    current_hashes=current_hashes,
                    reference_hashes=reference_hashes,
                    changed_block_indices=changed_indices,
                    message="Допустимое изменение (режим обновления)"
                )
            
            # Вычисление энтропии для определения шифрования
            entropy = self.calculate_entropy(file_path)
            
            # Регистрация события модификации
            mod_event = ModificationEvent(
                file_path=file_path,
                timestamp=datetime.now(),
                blocks_changed=blocks_changed,
                blocks_total=blocks_total,
                change_percent=change_percent,
                entropy=entropy
            )
            self.modification_history.append(mod_event)
            
            # Определение критичности изменения
            change_type = self._classify_change(change_percent, entropy)
            
            return IntegrityCheckResult(
                file_path=file_path,
                change_type=change_type,
                blocks_total=blocks_total,
                blocks_changed=blocks_changed,
                change_percent=change_percent,
                current_hashes=current_hashes,
                reference_hashes=reference_hashes,
                changed_block_indices=changed_indices,
                entropy=entropy,
                message=self._get_change_message(change_type, change_percent, entropy)
            )
            
        except FileNotFoundError:
            return IntegrityCheckResult(
                file_path=file_path,
                change_type=ChangeType.CRITICAL_CHANGE,
                blocks_total=0,
                blocks_changed=0,
                change_percent=0.0,
                current_hashes=[],
                reference_hashes=reference_hashes,
                changed_block_indices=[],
                message="Файл удалён или недоступен"
            )
        except Exception as e:
            raise Exception(f"Ошибка проверки целостности {file_path}: {e}")
    
    def _classify_change(self, change_percent: float, entropy: float) -> ChangeType:
        """
        Классификация типа изменения
        
        Args:
            change_percent: процент изменённых блоков
            entropy: энтропия данных
            
        Returns:
            тип изменения
        """
        block_threshold = self.ransomware_thresholds['block_change_percent']
        entropy_threshold = self.ransomware_thresholds['entropy_threshold']
        
        # Критическое изменение: высокий процент изменений + высокая энтропия
        if change_percent >= block_threshold and entropy >= entropy_threshold:
            return ChangeType.CRITICAL_CHANGE
        
        # Подозрительное изменение: высокий процент изменений ИЛИ высокая энтропия
        if change_percent >= block_threshold or entropy >= entropy_threshold:
            return ChangeType.SUSPICIOUS_CHANGE
        
        # Обычное несанкционированное изменение
        return ChangeType.UNAUTHORIZED_CHANGE
    
    def _get_change_message(self, change_type: ChangeType, change_percent: float, entropy: float) -> str:
        """
        Формирование сообщения о типе изменения
        
        Args:
            change_type: тип изменения
            change_percent: процент изменений
            entropy: энтропия
            
        Returns:
            текстовое сообщение
        """
        if change_type == ChangeType.CRITICAL_CHANGE:
            return f"КРИТИЧЕСКОЕ ИЗМЕНЕНИЕ: {change_percent:.1f}% блоков, энтропия {entropy:.2f} (возможно шифрование)"
        elif change_type == ChangeType.SUSPICIOUS_CHANGE:
            return f"ПОДОЗРИТЕЛЬНОЕ ИЗМЕНЕНИЕ: {change_percent:.1f}% блоков, энтропия {entropy:.2f}"
        elif change_type == ChangeType.UNAUTHORIZED_CHANGE:
            return f"Несанкционированное изменение: {change_percent:.1f}% блоков"
        else:
            return "Неизвестный тип изменения"
    
    def detect_ransomware_pattern(self, time_window: Optional[int] = None) -> Tuple[bool, Dict]:
        """
        Обнаружение паттерна ransomware-атаки
        
        Признаки:
        - Массовое изменение файлов за короткий промежуток времени
        - Высокий процент изменённых блоков
        - Высокая энтропия данных
        
        Args:
            time_window: временное окно в секундах (если None - из конфигурации)
            
        Returns:
            (обнаружена ли атака, детали)
        """
        if time_window is None:
            time_window = self.ransomware_thresholds['time_window']
        
        now = datetime.now()
        threshold_time = now - timedelta(seconds=time_window)
        
        # Фильтрация событий в временном окне
        recent_events = [
            event for event in self.modification_history
            if event.timestamp >= threshold_time
        ]
        
        if len(recent_events) < self.ransomware_thresholds['files_count']:
            return False, {}
        
        # Анализ событий
        files_count = len(recent_events)
        avg_change_percent = sum(e.change_percent for e in recent_events) / files_count
        avg_entropy = sum(e.entropy for e in recent_events) / files_count
        
        # Подсчёт критических изменений
        critical_changes = sum(
            1 for e in recent_events
            if e.change_percent >= self.ransomware_thresholds['block_change_percent']
            and e.entropy >= self.ransomware_thresholds['entropy_threshold']
        )
        
        # Определение атаки
        is_attack = (
            files_count >= self.ransomware_thresholds['files_count']
            and avg_change_percent >= self.ransomware_thresholds['block_change_percent']
            and critical_changes >= (files_count * 0.7)  # 70% файлов критически изменены
        )
        
        details = {
            'files_affected': files_count,
            'time_window_seconds': time_window,
            'avg_change_percent': avg_change_percent,
            'avg_entropy': avg_entropy,
            'critical_changes': critical_changes,
            'affected_files': [e.file_path for e in recent_events],
            'detection_time': now.isoformat()
        }
        
        return is_attack, details
    
    def get_changed_blocks_data(self, file_path: str, changed_indices: List[int]) -> Dict[int, bytes]:
        """
        Получение данных изменённых блоков
        
        Args:
            file_path: путь к файлу
            changed_indices: индексы изменённых блоков
            
        Returns:
            словарь {индекс_блока: данные_блока}
        """
        if not os.path.exists(file_path):
            return {}
        
        changed_blocks = {}
        
        try:
            with open(file_path, 'rb') as f:
                for index in changed_indices:
                    # Переход к началу блока
                    f.seek(index * self.block_size)
                    # Чтение блока
                    block_data = f.read(self.block_size)
                    changed_blocks[index] = block_data
            
            return changed_blocks
            
        except Exception as e:
            raise Exception(f"Ошибка чтения изменённых блоков {file_path}: {e}")
    
    def clear_modification_history(self):
        """Очистка истории модификаций"""
        self.modification_history.clear()
    
    def get_modification_statistics(self, time_window: int = 60) -> Dict:
        """
        Получение статистики модификаций за период
        
        Args:
            time_window: временное окно в секундах
            
        Returns:
            статистика
        """
        now = datetime.now()
        threshold_time = now - timedelta(seconds=time_window)
        
        recent_events = [
            event for event in self.modification_history
            if event.timestamp >= threshold_time
        ]
        
        if not recent_events:
            return {
                'files_modified': 0,
                'avg_change_percent': 0.0,
                'avg_entropy': 0.0,
                'time_window_seconds': time_window
            }
        
        return {
            'files_modified': len(recent_events),
            'avg_change_percent': sum(e.change_percent for e in recent_events) / len(recent_events),
            'avg_entropy': sum(e.entropy for e in recent_events) / len(recent_events),
            'max_change_percent': max(e.change_percent for e in recent_events),
            'max_entropy': max(e.entropy for e in recent_events),
            'time_window_seconds': time_window,
            'files': [e.file_path for e in recent_events]
        }