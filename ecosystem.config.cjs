module.exports = {
  apps: [{
    name: "telegram-app",
    script: "./dist/index.js",
    env: {
      NODE_ENV: "production",
      DATABASE_URL: "postgres://telegram_user:telegram_secure_pwd@localhost:5432/telegram_app",
      SESSION_SECRET: "jf93j4f9j34f9j34f9j34f9j34f9j34f",
      PORT: "5000",
      // Добавьте ваши реальные значения сюда:
      TELEGRAM_API_ID: "26566382",
      TELEGRAM_API_HASH: "373704562ab9b55f9338fc1b9352575e",
      // TELEGRAM_BOT_TOKEN: "your_telegram_bot_token_here", // Раскомментируйте, если нужно
      // VITE_TELEGRAM_BOT_ID: "your_telegram_bot_id_here", // Раскомментируйте, если нужно
    }
  }]
}