# Инструкция по развёртыванию приложения на сервере

Эта инструкция поможет вам развернуть приложение на вашем сервере без использования Docker.

## Требования

- Node.js 18+ (рекомендуется Node.js 20)
- npm 8+
- PostgreSQL 14+ установленный и запущенный

## Шаги по развертыванию

### 1. Подготовка сервера

Убедитесь, что на вашем сервере установлены необходимые компоненты:

```bash
# Проверка версии Node.js
node -v

# Проверка версии npm
npm -v

# Проверка доступности PostgreSQL
psql --version
```

### 2. Создание базы данных PostgreSQL

```bash
# Подключение к PostgreSQL
sudo -u postgres psql

# Создание базы данных
postgres=# CREATE DATABASE telegram_app;

# Создание пользователя с паролем (замените 'your_password' на безопасный пароль)
postgres=# CREATE USER telegram_user WITH PASSWORD 'your_password';

# Выдача привилегий пользователю на базу данных
postgres=# GRANT ALL PRIVILEGES ON DATABASE telegram_app TO telegram_user;

# Выход из PostgreSQL
postgres=# \q
```

### 3. Клонирование репозитория

```bash
# Клонирование репозитория в выбранную директорию
git clone https://your-repository-url.git telegram-app
cd telegram-app
```

### 4. Настройка переменных окружения

```bash
# Создание файла .env из примера
cp .env.example .env

# Отредактируйте файл .env, указав правильные значения
nano .env
```

Важные параметры для редактирования в `.env`:

```
# Основные настройки
NODE_ENV=production
SESSION_SECRET=your_secure_session_secret_here

# Настройки базы данных (замените на вашу конфигурацию)
DATABASE_URL=postgres://telegram_user:your_password@localhost:5432/telegram_app

# Настройки Telegram бота (замените на ваши значения)
TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here
VITE_TELEGRAM_BOT_ID=your_telegram_bot_id_here

# Настройки порта сервера (опционально)
PORT=5000
```

### 5. Запуск скрипта развертывания

```bash
# Сделайте скрипт исполняемым, если он еще не является таковым
chmod +x server-deploy.sh

# Запустите скрипт развертывания
./server-deploy.sh
```

Скрипт выполнит следующие действия:
- Установит зависимости
- Соберет приложение
- Применит миграции базы данных
- Создаст пользователя-администратора (если он еще не существует)

### 6. Запуск приложения

#### Для разработки:

```bash
npm run dev
```

#### Для продакшн:

```bash
npm start
```

### 7. Настройка процесс-менеджера (рекомендуется для production)

Для обеспечения работы приложения в фоновом режиме и автоматического перезапуска рекомендуется использовать PM2:

```bash
# Установка PM2
npm install -g pm2

# Запуск приложения через PM2
pm2 start npm --name "telegram-app" -- start

# Настройка автозапуска при перезагрузке сервера
pm2 startup
pm2 save
```

### 8. Настройка обратного прокси-сервера (опционально)

Для работы с доменным именем и SSL рекомендуется настроить Nginx:

```bash
# Установка Nginx
sudo apt update
sudo apt install nginx

# Создание конфигурации сайта
sudo nano /etc/nginx/sites-available/telegram-app
```

Пример конфигурации Nginx:

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

Активация конфигурации:

```bash
sudo ln -s /etc/nginx/sites-available/telegram-app /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 9. Настройка SSL с Let's Encrypt (рекомендуется для production)

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

## Обновление приложения

Когда вы хотите обновить приложение на сервере с новыми изменениями:

```bash
# Переход в директорию приложения
cd telegram-app

# Получение последних изменений
git pull

# Установка новых зависимостей
npm ci

# Сборка приложения
npm run build

# Применение миграций (если есть новые)
npm run db:push

# Перезапуск приложения (если используется PM2)
pm2 restart telegram-app
```

## Учетные данные по умолчанию

После первого развертывания будет создан пользователь-администратор со следующими учетными данными:

- Логин: `admin`
- Пароль: `admin`

**Внимание**: Обязательно измените пароль администратора после первого входа в систему!