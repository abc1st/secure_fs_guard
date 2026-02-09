#!/bin/bash
# scripts/uninstall.sh
# Удаление Secure FS Guard

set -e

echo "======================================"
echo "Secure FS Guard - Удаление"
echo "======================================"
echo

# Проверка root прав
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Ошибка: Скрипт должен быть запущен от имени root"
    echo "   Используйте: sudo $0"
    exit 1
fi

# Подтверждение
read -p "⚠️  Вы уверены, что хотите удалить Secure FS Guard? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Удаление отменено"
    exit 0
fi

echo
echo "[1/5] Остановка сервиса..."

systemctl stop secure-fs-guard 2>/dev/null || echo "  ℹ Сервис не запущен"
systemctl disable secure-fs-guard 2>/dev/null || echo "  ℹ Сервис не в автозагрузке"

echo "  ✓ Сервис остановлен"

echo "[2/5] Удаление systemd сервиса..."

rm -f /etc/systemd/system/secure-fs-guard.service
systemctl daemon-reload

echo "  ✓ Service файл удалён"

echo "[3/5] Удаление файлов программы..."

rm -rf /opt/secure_fs_guard
rm -f /usr/local/bin/secure-fs-guard-gui

echo "  ✓ Файлы программы удалены"

echo "[4/5] Удаление конфигурации и данных..."

read -p "Удалить конфигурацию (/etc/secure_fs_guard)? (yes/no): " del_config
if [ "$del_config" = "yes" ]; then
    rm -rf /etc/secure_fs_guard
    echo "  ✓ Конфигурация удалена"
else
    echo "  ℹ Конфигурация сохранена"
fi

read -p "Удалить данные (/var/lib/secure_fs_guard)? (yes/no): " del_data
if [ "$del_data" = "yes" ]; then
    rm -rf /var/lib/secure_fs_guard
    echo "  ✓ Данные удалены"
else
    echo "  ℹ Данные сохранены"
fi

read -p "Удалить логи (/var/log/secure_fs_guard)? (yes/no): " del_logs
if [ "$del_logs" = "yes" ]; then
    rm -rf /var/log/secure_fs_guard
    echo "  ✓ Логи удалены"
else
    echo "  ℹ Логи сохранены"
fi

echo "[5/5] Очистка IPC socket..."

rm -f /var/run/secure_fs_guard.sock

echo "  ✓ Socket удалён"

echo
echo "======================================"
echo "✓ Удаление завершено"
echo "======================================"
echo