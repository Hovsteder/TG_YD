import { Bot, session, GrammyError, HttpError } from "grammy";
import { storage } from "./storage";
import crypto from "crypto";

// Проверка наличия токена Telegram API
if (!process.env.TELEGRAM_BOT_TOKEN) {
  throw new Error("TELEGRAM_BOT_TOKEN must be set");
}

// Создание экземпляра бота
const bot = new Bot(process.env.TELEGRAM_BOT_TOKEN);

// Хранилище для временных 2FA кодов
type TwoFAData = {
  code: string;
  expiresAt: Date;
  attempts: number;
};

const twoFAStore: Record<string, TwoFAData> = {};

// Генерация и сохранение 2FA кода
export async function generateTwoFACode(telegramId: string): Promise<string> {
  // Генерация 5-значного кода
  const code = Math.floor(10000 + Math.random() * 90000).toString();
  
  // Сохранение кода в хранилище с временем жизни 5 минут
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  twoFAStore[telegramId] = { code, expiresAt, attempts: 0 };
  
  try {
    // Отправка кода пользователю через Telegram
    await bot.api.sendMessage(telegramId, `Ваш код подтверждения: ${code}\nДействителен в течение 5 минут.`);
    
    // Обновление кода в базе данных
    const user = await storage.getUserByTelegramId(telegramId);
    if (user) {
      await storage.updateUser(user.id, { twoFaCode: code });
      
      // Логирование действия
      await storage.createLog({
        userId: user.id,
        action: "2fa_code_sent",
        details: { telegram_id: telegramId },
        ipAddress: null
      });
    }
    
    return code;
  } catch (error) {
    console.error("Error sending 2FA code:", error);
    if (error instanceof GrammyError) {
      console.error("Error in Telegram API:", error.description);
    } else if (error instanceof HttpError) {
      console.error("HTTP error:", error);
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
    const user = await bot.api.getChat(telegramId);
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
export function validateTelegramAuth(authData: any): boolean {
  const { id, first_name, username, photo_url, auth_date, hash } = authData;
  
  // Проверяем наличие обязательных полей
  if (!id || !auth_date || !hash || !process.env.TELEGRAM_BOT_TOKEN) {
    return false;
  }
  
  // Проверяем, что auth_date не старше 24 часов
  const currentTime = Math.floor(Date.now() / 1000);
  if (currentTime - parseInt(auth_date) > 86400) {
    return false;
  }
  
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
    .update(process.env.TELEGRAM_BOT_TOKEN)
    .digest();
  
  // Вычисляем хеш и сравниваем с полученным
  const hash_check = crypto.createHmac('sha256', secret)
    .update(data_check_string)
    .digest('hex');
  
  return hash === hash_check;
}

export default bot;
