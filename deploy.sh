#!/bin/bash

set -e

# Название проекта
PROJECT_NAME="telegram-chat-manager"

# Вывод сообщения о начале работы
echo "Starting deployment of $PROJECT_NAME..."

# Проверка наличия необходимых программ
if ! command -v docker &> /dev/null; then
    echo "Docker not found! Please install Docker before proceeding."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "Docker Compose not found! Please install Docker Compose before proceeding."
    exit 1
fi

# Проверка наличия .env файла
if [ ! -f .env ]; then
    echo "Creating .env file from example..."
    cp .env.example .env
    echo "Please edit the .env file with your actual secrets before continuing!"
    exit 1
fi

# Сборка и запуск контейнеров
echo "Building and starting containers..."
docker-compose up -d --build

# Инициализация базы данных
echo "Initializing database (this may take a moment)..."
sleep 10 # Даем базе время на запуск
docker-compose exec app chmod +x init-db.sh
docker-compose exec app ./init-db.sh

echo "Deployment completed successfully!"
echo "Your application is now running at http://localhost:5000"
echo "Default admin credentials: admin/admin (Please change this after first login!)"