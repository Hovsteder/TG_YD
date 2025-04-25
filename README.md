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

### Установка

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

6. Для сборки проекта
   ```
   npm run build
   ```

## Структура проекта

- `/client` - React frontend
- `/server` - Express backend
- `/shared` - Общие типы и схемы данных

## Административный доступ

По умолчанию создается администратор со следующими учетными данными:
- Логин: admin
- Пароль: admin

**Рекомендуется** сменить пароль после первого входа через панель администратора.