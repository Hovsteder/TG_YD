#!/bin/bash

# Скрипт для развертывания приложения на сервере без Docker

set -e

# Название проекта
PROJECT_NAME="telegram-chat-manager"

# Вывод сообщения о начале работы
echo "Starting deployment of $PROJECT_NAME..."

# Проверка наличия необходимых программ
if ! command -v node &> /dev/null; then
    echo "Node.js not found! Please install Node.js before proceeding."
    exit 1
fi

if ! command -v npm &> /dev/null; then
    echo "npm not found! Please install npm before proceeding."
    exit 1
fi

# Проверка версии Node.js (рекомендуется v20+)
NODE_VERSION=$(node -v | cut -d "v" -f2 | cut -d "." -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "Warning: Node.js version is below 18. Recommended version is 20 or higher."
    read -p "Do you want to continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Проверка наличия .env файла
if [ ! -f .env ]; then
    echo "Creating .env file from example..."
    cp .env.example .env
    echo "Please edit the .env file with your actual secrets before continuing!"
    exit 1
fi

# Установка зависимостей
echo "Installing dependencies..."
npm ci

# Сборка приложения
echo "Building application..."
npm run build

# Проверка настройки базы данных
echo "Checking database configuration..."
if ! grep -q "DATABASE_URL" .env; then
    echo "DATABASE_URL not found in .env file. Please add your database connection string."
    echo "Example: DATABASE_URL=postgres://username:password@localhost:5432/telegram_app"
    exit 1
fi

# Применение миграций базы данных
echo "Applying database migrations..."
npm run db:push

# Создание администратора, если не существует
echo "Creating default admin user if it doesn't exist..."
node -e "
const { db } = require('./server/db.js');
const { eq } = require('drizzle-orm');
const { users } = require('./shared/schema.js');
const { scrypt, randomBytes } = require('crypto');
const { promisify } = require('util');

const scryptAsync = promisify(scrypt);

async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const buf = await scryptAsync(password, salt, 64);
  return \`\${buf.toString('hex')}.\${salt}\`;
}

async function main() {
  try {
    // Проверяем, существует ли пользователь admin
    const adminUser = await db.select().from(users).where(eq(users.username, 'admin')).limit(1);
    
    if (adminUser.length === 0) {
      console.log('Creating default admin user...');
      // Создаем хеш пароля 'admin'
      const hashedPassword = await hashPassword('admin');
      
      // Добавляем пользователя admin
      await db.insert(users).values({
        username: 'admin',
        password: hashedPassword,
        isAdmin: true,
        isActive: true,
        createdAt: new Date().toISOString(),
      });
      
      console.log('Default admin user created successfully!');
    } else {
      console.log('Admin user already exists, skipping creation.');
    }
  } catch (error) {
    console.error('Error initializing database:', error);
    process.exit(1);
  }
}

main();
"

echo "Deployment completed successfully!"
echo "To start the application in development mode:"
echo "  npm run dev"
echo ""
echo "To start the application in production mode:"
echo "  npm start"
echo ""
echo "Default admin credentials: admin/admin (Please change this after first login!)"