#!/bin/bash
# scripts/setup_dev.sh
# Настройка окружения разработки

set -e

echo "======================================"
echo "Secure FS Guard - Настройка для разработки"
echo "======================================"
echo

# Определение директории проекта
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Директория проекта: $PROJECT_DIR"
echo

echo "[1/4] Создание локальных директорий..."

mkdir -p "$PROJECT_DIR/config"
mkdir -p "$PROJECT_DIR/storage/backups"
mkdir -p "$PROJECT_DIR/logs"

echo "  ✓ Директории созданы"

echo "[2/4] Создание конфигурации для разработки..."

cat > "$PROJECT_DIR/config/system.yaml" << 'EOF'
protected_paths:
  - ./test_data

block_config:
  size: 65536
  algorithm: sha256

ransomware_thresholds:
  files_count: 5
  time_window: 10
  block_change_percent: 70
  entropy_threshold: 7.5

monitoring:
  fallback_interval: 10
  use_inotify: true

storage_path: ./storage
log_path: ./logs/system.log
ipc_socket: /tmp/secure_fs_guard_dev.sock
EOF

echo "  ✓ Конфигурация создана"

echo "[3/4] Создание тестовых данных..."

mkdir -p "$PROJECT_DIR/test_data"

cat > "$PROJECT_DIR/test_data/example.txt" << 'EOF'
This is a test file for Secure FS Guard.
This content will be monitored for changes.
EOF

cat > "$PROJECT_DIR/test_data/important.txt" << 'EOF'
Important data that should be protected.
Any unauthorized changes will be detected and reverted.
EOF

echo "  ✓ Тестовые данные созданы"

echo "[4/4] Установка Python зависимостей..."

pip3 install -r "$PROJECT_DIR/requirements.txt" --break-system-packages 2>/dev/null || \
pip3 install -r "$PROJECT_DIR/requirements.txt" || \
echo "  ⚠ Установите зависимости вручную: pip3 install -r requirements.txt"

echo "  ✓ Зависимости установлены"

echo
echo "======================================"
echo "✓ Окружение разработки готово!"
echo "======================================"
echo
echo "Для запуска в режиме разработки:"
echo
echo "1. Запуск службы:"
echo "   sudo python3 daemon/main.py --config config/system.yaml"
echo
echo "2. Запуск GUI:"
echo "   python3 gui/gui_main.py"
echo
echo "Тестовые данные находятся в: $PROJECT_DIR/test_data"
echo "Логи: $PROJECT_DIR/logs/system.log"
echo