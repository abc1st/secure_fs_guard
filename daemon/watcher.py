# daemon/watcher.py

import os
import time
import threading
from pathlib import Path
from typing import Callable, Set, List, Optional, Dict
from queue import Queue, Empty
from enum import Enum
import select

try:
    import inotify.adapters
    import inotify.constants
    INOTIFY_AVAILABLE = True
except ImportError:
    INOTIFY_AVAILABLE = False
    print("WARNING: inotify не установлен, используется только fallback режим")

class WatchEventType(Enum):
    """Типы событий мониторинга"""
    MODIFY = "MODIFY"
    WRITE = "WRITE"
    CLOSE_WRITE = "CLOSE_WRITE"
    DELETE = "DELETE"
    MOVE = "MOVE"
    CREATE = "CREATE"

class WatchEvent:
    """Событие изменения файла"""
    def __init__(self, event_type: WatchEventType, file_path: str, timestamp: float = None):
        self.event_type = event_type
        self.file_path = file_path
        self.timestamp = timestamp or time.time()
    
    def __repr__(self):
        return f"WatchEvent({self.event_type.value}, {self.file_path})"

class FileWatcher:
    """
    Отслеживание изменений файлов
    
    Использует:
    - inotify для реального времени
    - периодическую проверку (fallback)
    
    Отвечает за:
    - фиксацию факта изменения
    - передачу события в обработчик
    """
    
    def __init__(self, 
                 protected_paths: List[str],
                 callback: Callable[[WatchEvent], None],
                 use_inotify: bool = True,
                 fallback_interval: int = 60):
        """
        Args:
            protected_paths: список защищаемых путей
            callback: функция обработки события изменения
            use_inotify: использовать inotify (если доступен)
            fallback_interval: интервал периодической проверки в секундах
        """
        self.protected_paths = protected_paths
        self.callback = callback
        self.use_inotify = use_inotify and INOTIFY_AVAILABLE
        self.fallback_interval = fallback_interval
        
        # Состояние мониторинга
        self.is_running = False
        self.is_paused = False
        
        # Потоки
        self.inotify_thread: Optional[threading.Thread] = None
        self.fallback_thread: Optional[threading.Thread] = None
        
        # Для inotify
        self.inotify_adapter = None
        self.watched_paths: Set[str] = set()
        
        # Для fallback
        self.file_states: Dict[str, Dict] = {}  # {file_path: {mtime, size, ...}}
        
        # Очередь событий
        self.event_queue: Queue = Queue()
        self.event_processor_thread: Optional[threading.Thread] = None
        
        # Дедупликация событий
        self.recent_events: Dict[str, float] = {}  # {file_path: timestamp}
        self.dedup_window = 2.0  # секунды
    
    def start(self):
        """Запуск мониторинга"""
        if self.is_running:
            return
        
        self.is_running = True
        self.is_paused = False
        
        # Инициализация состояний файлов
        self._init_file_states()
        
        # Запуск обработчика событий
        self.event_processor_thread = threading.Thread(
            target=self._event_processor,
            daemon=True,
            name="EventProcessor"
        )
        self.event_processor_thread.start()
        
        # Запуск inotify (если доступен)
        if self.use_inotify:
            self.inotify_thread = threading.Thread(
                target=self._inotify_monitor,
                daemon=True,
                name="InotifyMonitor"
            )
            self.inotify_thread.start()
        
        # Запуск fallback проверки
        self.fallback_thread = threading.Thread(
            target=self._fallback_monitor,
            daemon=True,
            name="FallbackMonitor"
        )
        self.fallback_thread.start()
    
    def stop(self):
        """Остановка мониторинга"""
        self.is_running = False
        
        # Ожидание завершения потоков
        if self.inotify_thread and self.inotify_thread.is_alive():
            self.inotify_thread.join(timeout=2)
        
        if self.fallback_thread and self.fallback_thread.is_alive():
            self.fallback_thread.join(timeout=2)
        
        if self.event_processor_thread and self.event_processor_thread.is_alive():
            self.event_processor_thread.join(timeout=2)
    
    def pause(self):
        """Приостановка мониторинга (события игнорируются)"""
        self.is_paused = True
    
    def resume(self):
        """Возобновление мониторинга"""
        self.is_paused = False
    
    def add_path(self, path: str):
        """Добавление пути в список мониторинга"""
        if path not in self.protected_paths:
            self.protected_paths.append(path)
            
            # Добавление в inotify (если запущен)
            if self.use_inotify and self.inotify_adapter:
                self._add_inotify_watch(path)
            
            # Обновление состояний файлов
            self._update_file_states_for_path(path)
    
    def remove_path(self, path: str):
        """Удаление пути из списка мониторинга"""
        if path in self.protected_paths:
            self.protected_paths.remove(path)
            
            # Удаление из inotify
            if self.use_inotify and self.inotify_adapter:
                self._remove_inotify_watch(path)
            
            # Удаление состояний файлов
            self._remove_file_states_for_path(path)
    
    def _init_file_states(self):
        """Инициализация состояний всех защищаемых файлов"""
        self.file_states.clear()
        
        for base_path in self.protected_paths:
            self._update_file_states_for_path(base_path)
    
    def _update_file_states_for_path(self, base_path: str):
        """Обновление состояний файлов для конкретного пути"""
        expanded_path = os.path.expanduser(base_path)
        
        if os.path.isfile(expanded_path):
            self._record_file_state(expanded_path)
        elif os.path.isdir(expanded_path):
            for root, dirs, files in os.walk(expanded_path):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    self._record_file_state(file_path)
    
    def _remove_file_states_for_path(self, base_path: str):
        """Удаление состояний файлов для конкретного пути"""
        expanded_path = os.path.expanduser(base_path)
        
        # Удаление всех файлов, начинающихся с этого пути
        to_remove = [
            fp for fp in self.file_states.keys()
            if fp.startswith(expanded_path)
        ]
        
        for fp in to_remove:
            del self.file_states[fp]
    
    def _record_file_state(self, file_path: str):
        """Запись текущего состояния файла"""
        try:
            stat = os.stat(file_path)
            self.file_states[file_path] = {
                'mtime': stat.st_mtime,
                'size': stat.st_size,
                'inode': stat.st_ino
            }
        except (OSError, FileNotFoundError):
            # Файл удалён или недоступен
            if file_path in self.file_states:
                del self.file_states[file_path]
    
    def _inotify_monitor(self):
        """Поток мониторинга через inotify"""
        if not INOTIFY_AVAILABLE:
            return
        
        try:
            # Создание inotify адаптера
            self.inotify_adapter = inotify.adapters.Inotify()
            
            # Добавление путей в мониторинг
            for path in self.protected_paths:
                self._add_inotify_watch(path)
            
            # Основной цикл мониторинга
            while self.is_running:
                # Проверка событий с таймаутом
                events = self.inotify_adapter.event_gen(yield_nones=False, timeout_s=1)
                
                for event in events:
                    if not self.is_running:
                        break
                    
                    self._process_inotify_event(event)
        
        except Exception as e:
            print(f"Ошибка inotify мониторинга: {e}")
        
        finally:
            # Очистка
            if self.inotify_adapter:
                for path in list(self.watched_paths):
                    try:
                        self.inotify_adapter.remove_watch(path)
                    except:
                        pass
    
    def _add_inotify_watch(self, path: str):
        """Добавление пути в inotify"""
        if not self.inotify_adapter:
            return
        
        expanded_path = os.path.expanduser(path)
        
        try:
            if os.path.isfile(expanded_path):
                # Мониторинг файла
                self.inotify_adapter.add_watch(
                    expanded_path.encode('utf-8'),
                    mask=inotify.constants.IN_MODIFY | 
                         inotify.constants.IN_CLOSE_WRITE |
                         inotify.constants.IN_DELETE_SELF |
                         inotify.constants.IN_MOVE_SELF
                )
                self.watched_paths.add(expanded_path)
            
            elif os.path.isdir(expanded_path):
                # Рекурсивный мониторинг директории
                self.inotify_adapter.add_watch(
                    expanded_path.encode('utf-8'),
                    mask=inotify.constants.IN_MODIFY |
                         inotify.constants.IN_CLOSE_WRITE |
                         inotify.constants.IN_DELETE |
                         inotify.constants.IN_CREATE |
                         inotify.constants.IN_MOVED_FROM |
                         inotify.constants.IN_MOVED_TO
                )
                self.watched_paths.add(expanded_path)
                
                # Добавление всех поддиректорий
                for root, dirs, files in os.walk(expanded_path):
                    for dirname in dirs:
                        dir_path = os.path.join(root, dirname)
                        self.inotify_adapter.add_watch(
                            dir_path.encode('utf-8'),
                            mask=inotify.constants.IN_MODIFY |
                                 inotify.constants.IN_CLOSE_WRITE |
                                 inotify.constants.IN_DELETE |
                                 inotify.constants.IN_CREATE |
                                 inotify.constants.IN_MOVED_FROM |
                                 inotify.constants.IN_MOVED_TO
                        )
                        self.watched_paths.add(dir_path)
        
        except Exception as e:
            print(f"Ошибка добавления watch для {path}: {e}")
    
    def _remove_inotify_watch(self, path: str):
        """Удаление пути из inotify"""
        if not self.inotify_adapter:
            return
        
        expanded_path = os.path.expanduser(path)
        
        try:
            if expanded_path in self.watched_paths:
                self.inotify_adapter.remove_watch(expanded_path.encode('utf-8'))
                self.watched_paths.remove(expanded_path)
        except Exception as e:
            print(f"Ошибка удаления watch для {path}: {e}")
    
    def _process_inotify_event(self, event):
        """Обработка события inotify"""
        (header, type_names, watch_path, filename) = event
        
        # Формирование полного пути
        if filename:
            file_path = os.path.join(watch_path.decode('utf-8'), filename.decode('utf-8'))
        else:
            file_path = watch_path.decode('utf-8')
        
        # Фильтрация директорий
        if os.path.isdir(file_path):
            return
        
        # Определение типа события
        event_type = None
        
        if 'IN_MODIFY' in type_names or 'IN_CLOSE_WRITE' in type_names:
            event_type = WatchEventType.MODIFY
        elif 'IN_DELETE' in type_names or 'IN_DELETE_SELF' in type_names:
            event_type = WatchEventType.DELETE
        elif 'IN_MOVED_FROM' in type_names or 'IN_MOVED_TO' in type_names or 'IN_MOVE_SELF' in type_names:
            event_type = WatchEventType.MOVE
        elif 'IN_CREATE' in type_names:
            event_type = WatchEventType.CREATE
        
        if event_type:
            self._queue_event(WatchEvent(event_type, file_path))
    
    def _fallback_monitor(self):
        """Поток периодической проверки (fallback)"""
        while self.is_running:
            try:
                # Проверка каждого защищаемого пути
                for base_path in self.protected_paths:
                    if not self.is_running:
                        break
                    
                    self._check_path_changes(base_path)
                
                # Ожидание следующего цикла
                time.sleep(self.fallback_interval)
            
            except Exception as e:
                print(f"Ошибка fallback мониторинга: {e}")
                time.sleep(5)
    
    def _check_path_changes(self, base_path: str):
        """Проверка изменений в пути"""
        expanded_path = os.path.expanduser(base_path)
        
        if os.path.isfile(expanded_path):
            self._check_file_change(expanded_path)
        
        elif os.path.isdir(expanded_path):
            # Проверка всех файлов в директории
            try:
                for root, dirs, files in os.walk(expanded_path):
                    for filename in files:
                        file_path = os.path.join(root, filename)
                        self._check_file_change(file_path)
            except Exception as e:
                print(f"Ошибка обхода директории {expanded_path}: {e}")
    
    def _check_file_change(self, file_path: str):
        """Проверка изменения конкретного файла"""
        try:
            current_stat = os.stat(file_path)
            current_state = {
                'mtime': current_stat.st_mtime,
                'size': current_stat.st_size,
                'inode': current_stat.st_ino
            }
            
            # Проверка наличия предыдущего состояния
            if file_path not in self.file_states:
                # Новый файл
                self.file_states[file_path] = current_state
                self._queue_event(WatchEvent(WatchEventType.CREATE, file_path))
                return
            
            previous_state = self.file_states[file_path]
            
            # Проверка изменений
            if (current_state['mtime'] != previous_state['mtime'] or
                current_state['size'] != previous_state['size']):
                # Файл изменён
                self.file_states[file_path] = current_state
                self._queue_event(WatchEvent(WatchEventType.MODIFY, file_path))
        
        except FileNotFoundError:
            # Файл удалён
            if file_path in self.file_states:
                del self.file_states[file_path]
                self._queue_event(WatchEvent(WatchEventType.DELETE, file_path))
        
        except Exception as e:
            # Ошибка доступа к файлу
            pass
    
    def _queue_event(self, event: WatchEvent):
        """Добавление события в очередь с дедупликацией"""
        current_time = time.time()
        
        # Проверка дедупликации
        if event.file_path in self.recent_events:
            last_event_time = self.recent_events[event.file_path]
            if (current_time - last_event_time) < self.dedup_window:
                # Игнорируем дублирующееся событие
                return
        
        # Запись времени события
        self.recent_events[event.file_path] = current_time
        
        # Добавление в очередь
        self.event_queue.put(event)
    
    def _event_processor(self):
        """Поток обработки событий из очереди"""
        while self.is_running:
            try:
                # Получение события с таймаутом
                event = self.event_queue.get(timeout=1)
                
                # Проверка паузы
                if self.is_paused:
                    continue
                
                # Вызов callback
                try:
                    self.callback(event)
                except Exception as e:
                    print(f"Ошибка обработки события {event}: {e}")
                
            except Empty:
                # Таймаут - продолжаем
                continue
            except Exception as e:
                print(f"Ошибка в event processor: {e}")
    
    def get_statistics(self) -> Dict:
        """Получение статистики мониторинга"""
        return {
            'is_running': self.is_running,
            'is_paused': self.is_paused,
            'inotify_enabled': self.use_inotify,
            'inotify_available': INOTIFY_AVAILABLE,
            'protected_paths_count': len(self.protected_paths),
            'watched_files_count': len(self.file_states),
            'watched_inotify_paths': len(self.watched_paths),
            'pending_events': self.event_queue.qsize(),
            'fallback_interval': self.fallback_interval
        }