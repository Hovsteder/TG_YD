# Telegram Chat Management System

Web-приложение для управления Telegram-чатами с двухфакторной аутентификацией и административными функциями.

## Возможности

- Аутентификация через Telegram
- Двухфакторная аутентификация
- Просмотр и управление чатами пользователей
- Административная панель с мониторингом
- Управление сессиями пользователей
- Отправка уведомлений о новых пользователях

## Установка и запуск

### Требования

- Node.js 16+
- PostgreSQL 12+

или

- Docker и Docker Compose (рекомендуется)

### Установка с использованием Docker (рекомендуется)

1. Клонировать репозиторий
   ```
   git clone <repository-url>
   cd telegram-chat-management
   ```

2. Создать файл .env из примера
   ```
   cp .env.example .env
   ```

3. Отредактировать файл .env, вставив реальные значения ключей
   ```
   # Обязательно измените значения переменных на настоящие!
   TELEGRAM_BOT_TOKEN=your_telegram_bot_token
   VITE_TELEGRAM_BOT_ID=your_telegram_bot_id
   SESSION_SECRET=random_secure_string
   ```

4. Запустить скрипт развертывания
   ```
   chmod +x deploy.sh
   ./deploy.sh
   ```

5. После успешного запуска, приложение будет доступно по адресу: http://localhost:5000

### Ручная установка

1. Клонировать репозиторий
   ```
   git clone <repository-url>
   cd telegram-chat-management
   ```

2. Установить зависимости
   ```
   npm install
   ```

3. Создать файл .env с переменными окружения
   ```
   # База данных
   DATABASE_URL=postgresql://username:password@localhost:5432/dbname
   
   # Telegram бот
   TELEGRAM_BOT_TOKEN=your_telegram_bot_token
   VITE_TELEGRAM_BOT_ID=your_telegram_bot_id
   
   # Сессии
   SESSION_SECRET=random_session_secret
   ```

4. Запустить миграции базы данных
   ```
   npm run db:push
   ```

5. Запустить приложение в режиме разработки
   ```
   npm run dev
   ```

6. Для продакшн сборки
   ```
   npm run build
   npm start
   ```

## Структура проекта

- `/client` - React frontend
- `/server` - Express backend
- `/shared` - Общие типы и схемы данных
- `Dockerfile` - Инструкции для сборки Docker-образа
- `docker-compose.yml` - Конфигурация для оркестрации контейнеров
- `deploy.sh` - Скрипт автоматического развертывания

## Административный доступ

По умолчанию создается администратор со следующими учетными данными:
- Логин: admin
- Пароль: admin

**Рекомендуется** сменить пароль после первого входа через панель администратора.

## Docker

### Структура Docker-конфигурации

Проект содержит следующие Docker-файлы:

- `Dockerfile` - Инструкции для сборки образа приложения
- `docker-compose.yml` - Конфигурация для оркестрации контейнеров (приложение + база данных)
- `.env.example` - Пример файла с переменными окружения

### Управление Docker-контейнерами

```bash
# Запуск контейнеров
docker-compose up -d

# Просмотр логов
docker-compose logs -f app

# Остановка контейнеров
docker-compose down

# Перезапуск сервиса приложения
docker-compose restart app

# Просмотр статуса контейнеров
docker-compose ps
```

### Резервное копирование базы данных

```bash
# Создание резервной копии
docker-compose exec db pg_dump -U postgres telegram_app > backup.sql

# Восстановление из резервной копии
docker-compose exec -T db psql -U postgres telegram_app < backup.sql
```