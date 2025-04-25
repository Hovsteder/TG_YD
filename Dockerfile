FROM node:20-alpine

WORKDIR /app

# Установка необходимых системных пакетов
RUN apk add --no-cache curl

# Установка зависимостей
COPY package.json package-lock.json ./
RUN npm ci

# Копирование исходных файлов
COPY . .

# Сборка приложения
RUN npm run build

# Открытие порта
EXPOSE 5000

# Запуск приложения
CMD ["npm", "start"]