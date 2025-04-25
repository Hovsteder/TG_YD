#!/bin/bash

set -e

echo "Initializing database..."

# Применяем миграции с помощью Drizzle
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

echo "Database initialization completed."