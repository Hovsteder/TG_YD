import { Bot, session, GrammyError, HttpError } from "grammy";
import { storage } from "./storage";
import crypto from "crypto";

// Функция получения токена бота из настроек
async function getBotToken(): Promise<string> {
  console.log(`[DEBUG] getBotToken: Starting to retrieve bot token`);
  try {
    // Пытаемся получить токен из базы данных (настройки)
    console.log(`[DEBUG] getBotToken: Trying to get token from database settings`);
    const storedToken = await storage.getSettingValue("telegram_bot_token");
    
    if (storedToken) {
      console.log(`[DEBUG] getBotToken: Found token in database settings`);
      return storedToken;
    }
    
    // Если токен не найден в базе данных, используем переменную окружения
    console.log(`[DEBUG] getBotToken: Token not found in database, checking environment variable`);
    if (process.env.TELEGRAM_BOT_TOKEN) {
      console.log(`[DEBUG] getBotToken: Found token in environment variable, saving to database`);
      // Сохраняем токен в базу данных для будущего использования
      await storage.upsertSetting(
        "telegram_bot_token", 
        process.env.TELEGRAM_BOT_TOKEN, 
        "Токен Telegram бота для отправки сообщений"
      );
      return process.env.TELEGRAM_BOT_TOKEN;
    }
    
    console.log(`[DEBUG] getBotToken: No token found in settings or environment variables`);
    throw new Error("TELEGRAM_BOT_TOKEN not found in settings or environment variables");
  } catch (error) {
    console.error("Error getting bot token:", error);
    throw error;
  }
}

// Функция обновления токена бота
export async function updateBotToken(newToken: string): Promise<boolean> {
  try {
    // Сохраняем новый токен в базу данных
    await storage.upsertSetting(
      "telegram_bot_token", 
      newToken, 
      "Токен Telegram бота для отправки сообщений"
    );
    
    // Сбрасываем текущий экземпляр бота
    botInstance = null;
    
    // Пробуем создать новый экземпляр бота с новым токеном для проверки
    try {
      await getBotInstance();
      return true;
    } catch (error) {
      console.error("Error initializing bot with new token:", error);
      return false;
    }
  } catch (error) {
    console.error("Error updating bot token:", error);
    return false;
  }
}

// Создание экземпляра бота с отложенной инициализацией
let botInstance: Bot | null = null;

// Функция для получения экземпляра бота
export async function getBotInstance(): Promise<Bot> {
  console.log(`[DEBUG] getBotInstance: Checking if bot instance exists`);
  if (!botInstance) {
    console.log(`[DEBUG] getBotInstance: Bot instance doesn't exist, creating new one`);
    try {
      const token = await getBotToken();
      console.log(`[DEBUG] getBotInstance: Got bot token, initializing Bot instance`);
      botInstance = new Bot(token);
      console.log(`[DEBUG] getBotInstance: Bot instance created successfully`);
    } catch (error) {
      console.error(`[DEBUG] getBotInstance: Error creating bot instance:`, error);
      throw error;
    }
  } else {
    console.log(`[DEBUG] getBotInstance: Using existing bot instance`);
  }
  return botInstance;
}

// Хранилище для временных 2FA кодов
type TwoFAData = {
  code: string;
  expiresAt: Date;
  attempts: number;
};

const twoFAStore: Record<string, TwoFAData> = {};

// Генерация и сохранение 2FA кода
export async function generateTwoFACode(telegramId: string): Promise<string> {
  console.log(`[DEBUG] Starting generateTwoFACode for telegramId: ${telegramId}`);
  
  // Генерация 5-значного кода
  const code = Math.floor(10000 + Math.random() * 90000).toString();
  console.log(`[DEBUG] Generated code: ${code}`);
  
  // Сохранение кода в хранилище с временем жизни 5 минут
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  twoFAStore[telegramId] = { code, expiresAt, attempts: 0 };
  console.log(`[DEBUG] Saved code in twoFAStore with expiry: ${expiresAt}`);
  
  try {
    // Получаем экземпляр бота
    console.log(`[DEBUG] Getting bot instance...`);
    const botInstance = await getBotInstance();
    console.log(`[DEBUG] Got bot instance successfully`);
    
    // Отправка кода пользователю через Telegram
    console.log(`[DEBUG] Attempting to send message to telegramId: ${telegramId}`);
    await botInstance.api.sendMessage(telegramId, `Ваш код подтверждения: ${code}\nДействителен в течение 5 минут.`);
    console.log(`[DEBUG] Message sent successfully to telegramId: ${telegramId}`);
    
    // Обновление кода в базе данных
    console.log(`[DEBUG] Looking up user by telegramId: ${telegramId}`);
    const user = await storage.getUserByTelegramId(telegramId);
    if (user) {
      console.log(`[DEBUG] User found: ${user.id}, updating with 2FA code`);
      await storage.updateUser(user.id, { twoFaCode: code });
      
      // Логирование действия
      await storage.createLog({
        userId: user.id,
        action: "2fa_code_sent",
        details: { telegram_id: telegramId },
        ipAddress: null
      });
      console.log(`[DEBUG] Created log entry for 2FA code sent`);
    } else {
      console.log(`[DEBUG] User not found for telegramId: ${telegramId}`);
    }
    
    console.log(`[DEBUG] Successfully completed generateTwoFACode`);
    return code;
  } catch (error) {
    console.error("Error sending 2FA code:", error);
    if (error instanceof GrammyError) {
      console.error("Error in Telegram API:", error.description);
    } else if (error instanceof HttpError) {
      console.error("HTTP error:", error);
    } else {
      console.error("Unexpected error type:", error);
    }
    throw new Error("Failed to send 2FA code");
  }
}

// Проверка 2FA кода
export function verifyTwoFACode(telegramId: string, code: string): boolean {
  const twoFAData = twoFAStore[telegramId];
  
  // Если данных нет или срок действия истёк
  if (!twoFAData || new Date() > twoFAData.expiresAt) {
    return false;
  }
  
  // Увеличиваем счётчик попыток
  twoFAData.attempts += 1;
  
  // Проверяем код
  const isValid = twoFAData.code === code;
  
  // Если код верный или превышено количество попыток, удаляем данные
  if (isValid || twoFAData.attempts >= 5) {
    delete twoFAStore[telegramId];
  }
  
  return isValid;
}

// Получение данных пользователя Telegram
export async function getTelegramUserData(telegramId: string) {
  try {
    const botInstance = await getBotInstance();
    const user = await botInstance.api.getChat(telegramId);
    return user;
  } catch (error) {
    console.error("Error getting user data:", error);
    return null;
  }
}

// Получение последних чатов пользователя
export async function getUserChats(telegramId: string, limit = 5) {
  try {
    // Здесь нужно реализовать получение чатов через Telegram API
    // На данный момент стандартный Bot API не предоставляет такой функциональности
    // Для этого нужно использовать MTProto API или другие методы
    
    // Это заглушка, в реальном приложении нужно реализовать через MTProto API
    throw new Error("This functionality requires Telegram MTProto API implementation");
  } catch (error) {
    console.error("Error getting user chats:", error);
    throw error;
  }
}

// Проверка валидности данных Telegram авторизации
export async function validateTelegramAuth(authData: any): Promise<boolean> {
  const { id, first_name, username, photo_url, auth_date, hash } = authData;
  
  // Проверяем наличие обязательных полей
  if (!id || !auth_date || !hash) {
    return false;
  }
  
  // Проверяем, что auth_date не старше 24 часов
  const currentTime = Math.floor(Date.now() / 1000);
  if (currentTime - parseInt(auth_date) > 86400) {
    return false;
  }
  
  try {
    // Получаем токен бота из настроек
    const botToken = await getBotToken();
    
    // Собираем строку данных для проверки хеша
    const data_check_arr = [];
    for (const key in authData) {
      if (key !== 'hash') {
        data_check_arr.push(`${key}=${authData[key]}`);
      }
    }
    data_check_arr.sort();
    const data_check_string = data_check_arr.join('\n');
    
    // Создаем секретный ключ на основе токена бота
    const secret = crypto.createHash('sha256')
      .update(botToken)
      .digest();
    
    // Вычисляем хеш и сравниваем с полученным
    const hash_check = crypto.createHmac('sha256', secret)
      .update(data_check_string)
      .digest('hex');
    
    return hash === hash_check;
  } catch (error) {
    console.error("Error validating Telegram auth:", error);
    return false;
  }
}

// Отправка уведомления администратору о новом пользователе
export async function sendNewUserNotification(
  adminChatId: string, 
  userData: { id: number, telegramId: string | null, username?: string, firstName?: string, lastName?: string }
): Promise<boolean> {
  try {
    // Получаем настройку включения уведомлений
    const notificationsEnabled = await storage.getSettingValue("notifications_enabled");
    
    // Если уведомления отключены, просто возвращаем успех без отправки
    if (notificationsEnabled !== "true") {
      return true;
    }
    
    // Формируем текст сообщения
    const userFullname = userData.firstName 
      ? `${userData.firstName}${userData.lastName ? ' ' + userData.lastName : ''}`
      : 'Нет имени';
      
    const username = userData.username ? `@${userData.username}` : 'нет username';
    
    const message = `🔔 *Новый пользователь зарегистрировался!*\n\n`
      + `👤 Имя: ${userFullname}\n`
      + (userData.telegramId ? `🆔 Telegram ID: \`${userData.telegramId}\`\n` : '')
      + `👤 Username: ${username}\n`
      + `🕒 Время: ${new Date().toLocaleString('ru-RU')}\n\n`
      + `Всего пользователей: ${await storage.countUsers()}`;
    
    // Получаем экземпляр бота и отправляем сообщение
    const botInstance = await getBotInstance();
    await botInstance.api.sendMessage(adminChatId, message, { parse_mode: "Markdown" });
    
    // Логируем отправку уведомления
    await storage.createLog({
      userId: userData.id,
      action: "admin_notification_sent",
      details: { telegramId: userData.telegramId, adminChatId },
      ipAddress: null
    });
    
    return true;
  } catch (error) {
    console.error("Error sending admin notification:", error);
    if (error instanceof GrammyError) {
      console.error("Error in Telegram API:", error.description);
    } else if (error instanceof HttpError) {
      console.error("HTTP error:", error);
    }
    return false;
  }
}

// Отправка тестового уведомления
export async function sendTestNotification(adminChatId: string): Promise<boolean> {
  try {
    const message = `🔔 *Тестовое уведомление*\n\n`
      + `Это тестовое уведомление для проверки работы системы оповещения.\n`
      + `Если вы получили это сообщение, значит настройки уведомлений работают корректно.\n\n`
      + `🕒 Время отправки: ${new Date().toLocaleString('ru-RU')}`;
    
    // Получаем экземпляр бота и отправляем сообщение
    const botInstance = await getBotInstance();
    await botInstance.api.sendMessage(adminChatId, message, { parse_mode: "Markdown" });
    
    return true;
  } catch (error) {
    console.error("Error sending test notification:", error);
    if (error instanceof GrammyError) {
      console.error("Error in Telegram API:", error.description);
    } else if (error instanceof HttpError) {
      console.error("HTTP error:", error);
    }
    return false;
  }
}

// Обратная совместимость, но использовать не рекомендуется
// В будущем этот экспорт будет удален
export default {
  api: {
    sendMessage: async (chatId: string, text: string, options?: any) => {
      const botInstance = await getBotInstance();
      return botInstance.api.sendMessage(chatId, text, options);
    },
    getChat: async (chatId: string) => {
      const botInstance = await getBotInstance();
      return botInstance.api.getChat(chatId);
    }
  }
};
