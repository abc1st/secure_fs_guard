#!/bin/bash
# scripts/install_service.sh
# Установка Secure FS Guard как системного сервиса

set -e

echo "======================================"
echo "Secure FS Guard - Установка сервиса"
echo "======================================"
echo

# Проверка root прав
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Ошибка: Скрипт должен быть запущен от имени root"
    echo "   Используйте: sudo $0"
    exit 1
fi

# Определение путей
INSTALL_DIR="/opt/secure_fs_guard"
CONFIG_DIR="/etc/secure_fs_guard"
DATA_DIR="/var/lib/secure_fs_guard"
LOG_DIR="/var/log/secure_fs_guard"

echo "[1/7] Создание директорий..."

# Создание директорий
mkdir -p "$INSTALL_DIR"/{daemon,gui/views}
mkdir -p "$CONFIG_DIR"
mkdir -p "$DATA_DIR"/{storage/backups,quarantine}
mkdir -p "$LOG_DIR"

echo "  ✓ Директории созданы"

echo "[2/7] Копирование файлов..."

# Определение исходной директории
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Копирование демона
cp -r "$SCRIPT_DIR"/daemon/*.py "$INSTALL_DIR/daemon/" 2>/dev/null || echo "  ⚠ Файлы демона уже существуют"

# Копирование GUI
cp -r "$SCRIPT_DIR"/gui/*.py "$INSTALL_DIR/gui/" 2>/dev/null || echo "  ⚠ Файлы GUI уже существуют"
cp -r "$SCRIPT_DIR"/gui/views/*.py "$INSTALL_DIR/gui/views/" 2>/dev/null || echo "  ⚠ Файлы views уже существуют"

# Копирование конфигурации (если не существует)
if [ ! -f "$CONFIG_DIR/system.yaml" ]; then
    cp "$SCRIPT_DIR/config/system.yaml" "$CONFIG_DIR/" 2>/dev/null || \
    cat > "$CONFIG_DIR/system.yaml" << 'EOF'
protected_paths:
  - /home/*/Documents
  - /home/*/important_data

block_config:
  size: 65536
  algorithm: sha256

ransomware_thresholds:
  files_count: 10
  time_window: 10
  block_change_percent: 70
  entropy_threshold: 7.5

monitoring:
  fallback_interval: 60
  use_inotify: true

storage_path: /var/lib/secure_fs_guard/storage
log_path: /var/log/secure_fs_guard/system.log
ipc_socket: /var/run/secure_fs_guard.sock
EOF
    echo "  ✓ Конфигурация создана"
else
    echo "  ℹ Конфигурация уже существует, пропускаем"
fi

echo "  ✓ Файлы скопированы"

echo "[3/7] Установка прав доступа..."

# Права на директории
chmod 755 "$INSTALL_DIR"
chmod 755 "$CONFIG_DIR"
chmod 700 "$DATA_DIR"
chmod 700 "$LOG_DIR"

# Права на конфигурацию
chmod 644 "$CONFIG_DIR/system.yaml"

# Права на исполняемые файлы
chmod +x "$INSTALL_DIR/daemon/main.py"
chmod +x "$INSTALL_DIR/gui/gui_main.py"

echo "  ✓ Права установлены"

echo "[4/7] Проверка зависимостей Python..."

# Проверка Python
if ! command -v python3 &> /dev/null; then
    echo "  ❌ Python 3 не найден. Установите: sudo apt install python3"
    exit 1
fi

# Проверка pip
if ! command -v pip3 &> /dev/null; then
    echo "  ⚠ pip3 не найден. Рекомендуется установить: sudo apt install python3-pip"
fi

# Установка зависимостей
echo "  Установка зависимостей..."
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    pip3 install -r "$SCRIPT_DIR/requirements.txt" --break-system-packages 2>/dev/null || \
    pip3 install -r "$SCRIPT_DIR/requirements.txt" || \
    echo "  ⚠ Некоторые зависимости не удалось установить"
else
    pip3 install PyYAML inotify --break-system-packages 2>/dev/null || \
    pip3 install PyYAML inotify || \
    echo "  ⚠ Некоторые зависимости не удалось установить"
fi

echo "  ✓ Зависимости проверены"

echo "[5/7] Создание systemd сервиса..."

# Создание service файла
cat > /etc/systemd/system/secure-fs-guard.service << EOF
[Unit]
Description=Secure FS Guard - File Integrity Monitoring System
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$INSTALL_DIR/daemon
ExecStart=/usr/bin/python3 $INSTALL_DIR/daemon/main.py --config $CONFIG_DIR/system.yaml
Restart=on-failure
RestartSec=10

# Безопасность
NoNewPrivileges=false
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

echo "  ✓ Service файл создан"

echo "[6/7] Перезагрузка systemd..."

systemctl daemon-reload

echo "  ✓ systemd перезагружен"

echo "[7/7] Создание alias для GUI..."

# Создание символической ссылки для удобного запуска GUI
ln -sf "$INSTALL_DIR/gui/gui_main.py" /usr/local/bin/secure-fs-guard-gui 2>/dev/null || true
chmod +x /usr/local/bin/secure-fs-guard-gui 2>/dev/null || true

echo "  ✓ Alias создан"

echo
echo "======================================"
echo "✓ Установка завершена успешно!"
echo "======================================"
echo
echo "Управление сервисом:"
echo "  Запуск:      sudo systemctl start secure-fs-guard"
echo "  Остановка:   sudo systemctl stop secure-fs-guard"
echo "  Автозапуск:  sudo systemctl enable secure-fs-guard"
echo "  Статус:      sudo systemctl status secure-fs-guard"
echo
echo "Запуск GUI:"
echo "  secure-fs-guard-gui"
echo "  или: python3 $INSTALL_DIR/gui/gui_main.py"
echo
echo "Конфигурация:"
echo "  $CONFIG_DIR/system.yaml"
echo
echo "Логи:"
echo "  $LOG_DIR/system.log"
echo "  journalctl -u secure-fs-guard -f"
echo
echo "Следующие шаги:"
echo "  1. Настройте защищаемые пути в $CONFIG_DIR/system.yaml"
echo "  2. Запустите сервис: sudo systemctl start secure-fs-guard"
echo "  3. Запустите GUI: secure-fs-guard-gui"
echo "  4. Войдите в режим инициализации и создайте эталон"
echo