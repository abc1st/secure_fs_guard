#!/bin/bash
# scripts/start_daemon.sh
# Ручной запуск демона Secure FS Guard

set -e

echo "======================================"
echo "Secure FS Guard - Запуск демона"
echo "======================================"
echo

# Проверка root прав
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Ошибка: Демон должен быть запущен от имени root"
    echo "   Используйте: sudo $0"
    exit 1
fi

# Определение директории скрипта
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Путь к демону
DAEMON_DIR="$SCRIPT_DIR/daemon"
CONFIG_FILE="${1:-/etc/secure_fs_guard/system.yaml}"

# Проверка существования файлов
if [ ! -f "$DAEMON_DIR/main.py" ]; then
    echo "❌ Ошибка: Файл демона не найден: $DAEMON_DIR/main.py"
    echo "   Убедитесь, что вы запускаете скрипт из корневой директории проекта"
    exit 1
fi

if [ ! -f "$CONFIG_FILE" ]; then
    echo "⚠ Предупреждение: Файл конфигурации не найден: $CONFIG_FILE"
    echo "   Будет использована конфигурация по умолчанию"
    echo
fi

echo "Конфигурация: $CONFIG_FILE"
echo "Рабочая директория: $DAEMON_DIR"
echo

# Проверка зависимостей
echo "Проверка зависимостей Python..."

if ! python3 -c "import yaml" 2>/dev/null; then
    echo "⚠ PyYAML не установлен. Установите: pip3 install PyYAML --break-system-packages"
fi

if ! python3 -c "import inotify" 2>/dev/null; then
    echo "⚠ inotify не установлен. Установите: pip3 install inotify --break-system-packages"
    echo "   (Система будет работать в режиме fallback)"
fi

echo

# Переход в директорию демона
cd "$DAEMON_DIR"

# Запуск демона
echo "Запуск демона..."
echo "Для остановки нажмите Ctrl+C"
echo
echo "--------------------------------------"
echo

python3 main.py --config "$CONFIG_FILE"