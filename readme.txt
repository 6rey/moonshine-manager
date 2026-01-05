# Moonshine Manager - Анализ проекта

## 📋 Обзор проекта

**Moonshine Manager** — это система управления виртуальными машинами (VDI) для удаленного игрового стриминга через Sunshine/Moonlight.

## 🏗️ Архитектура

### Компоненты:
1. **Backend API** (server/) - FastAPI сервер с PostgreSQL
2. **Python GUI клиент** (client/) - Desktop приложение на CustomTkinter
3. **JavaScript клиент** (client/js/) - Electron-подобное приложение
4. **Docker** (docker-compose.yml) - Окруженние для запуска

## 🎯 Основные функции

### Администрирование:
- ✅ Управление пользователями (admin/master/user роли)
- ✅ Регистрация и удаление VM
- ✅ Назначение VM пользователям
- ✅ Автоматическое обнаружение Sunshine хостов в сети

### Обнаружение хостов:
- **mDNS сканирование** (_nvstream._tcp.local.)
- **Port scanning** (порты 47989, 47984, 47990)
- **Multi-subnet поддержка** (настраиваемые подсети)
- **VPN-friendly** (увеличенные таймауты)

### Подключение:
- ✅ Автоматический pairing с Moonlight
- ✅ Streaming 1920x1080 @ 60 FPS
- ✅ Поддержка SSL verification toggle

## 📁 Структура файлов

```
moonshine-manager/
├── docker-compose.yml          # Docker окружение
├── eclypse.py                  # Основной клиент (Python)
├── eclypse_en.py               # English version
├── client/
│   ├── admin_sunshine.py       # Unified admin tool (1670+ строк)
│   ├── add_vm_gui.py           # VM discovery tool
│   ├── requirements.txt        # Python зависимости
│   └── js/                     # JS клиент
├── server/                     # FastAPI backend (пустая?)
└── docs/                       # Документация и скриншоты
```

## 🔧 Технологии

- **Backend**: FastAPI, PostgreSQL, JWT auth
- **Desktop GUI**: CustomTkinter (dark theme)
- **Network**: mDNS (zeroconf), socket scanning
- **Streaming**: Moonlight client integration
- **Config**: subnets.conf, client_config.txt

## 🚀 Ключевые особенности

1. **Unified Admin Tool** - объединяет admin-панель и VM discovery
2. **Auto-Discovery** - находит Sunshine хосты автоматически
3. **Role-based access** - разные интерфейсы для admin/master/user
4. **VPN-ready** - работает через VPN с увеличенными таймаутами
5. **SSL flexibility** - можно отключить проверку сертификатов

## 📊 Статистика проекта

- **Основной файл**: admin_sunshine.py (~1670 строк)
- **Язык**: Python 3.8+, JavaScript
- **GUI Framework**: CustomTkinter
- **API**: FastAPI (предположительно)

## 🎯 Назначение

Проект представляет собой полноценную систему управления игровыми VMI с:
- Автоматическим обнаружением хостов в сети
- Удобным интерфейсом для администраторов
- Гибкой системой прав доступа
- Поддержкой VPN и сложных сетевых топологий