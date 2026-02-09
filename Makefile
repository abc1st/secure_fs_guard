# Makefile

.PHONY: help install uninstall start stop status logs gui clean dev

help:
	@echo "Secure FS Guard - Команды управления"
	@echo ""
	@echo "Установка и управление:"
	@echo "  make install    - Установка системы"
	@echo "  make uninstall  - Удаление системы"
	@echo "  make start      - Запуск демона"
	@echo "  make stop       - Остановка демона"
	@echo "  make restart    - Перезапуск демона"
	@echo "  make status     - Статус сервиса"
	@echo "  make logs       - Просмотр логов"
	@echo ""
	@echo "Разработка:"
	@echo "  make dev        - Настройка окружения разработки"
	@echo "  make dev-start  - Запуск демона в dev режиме"
	@echo "  make gui        - Запуск GUI"
	@echo "  make clean      - Очистка временных файлов"

install:
	@sudo bash scripts/install_service.sh

uninstall:
	@sudo bash scripts/uninstall.sh

start:
	@sudo systemctl start secure-fs-guard
	@echo "✓ Демон запущен"

stop:
	@sudo systemctl stop secure-fs-guard
	@echo "✓ Демон остановлен"

restart:
	@sudo systemctl restart secure-fs-guard
	@echo "✓ Демон перезапущен"

status:
	@systemctl status secure-fs-guard

logs:
	@journalctl -u secure-fs-guard -f

gui:
	@python3 gui/gui_main.py

dev:
	@bash scripts/setup_dev.sh

dev-start:
	@sudo python3 daemon/main.py --config config/system.yaml

clean:
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@find . -type f -name "*.pyo" -delete 2>/dev/null || true
	@find . -type f -name "*.so" -delete 2>/dev/null || true
	@rm -f /tmp/secure_fs_guard_dev.sock 2>/dev/null || true
	@echo "✓ Временные файлы очищены"