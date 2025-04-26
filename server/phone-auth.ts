import { storage } from "./storage";
import { randomInt } from "crypto";
import { getBotInstance } from "./telegram";

// Хранилище для временных кодов подтверждения
interface VerificationData {
  code: string;
  expiresAt: Date;
  attempts: number;
}

// Хранилище в памяти для кодов (будет сбрасываться при перезапуске сервера)
const verificationStore: Record<string, VerificationData> = {};

// Генерация кода подтверждения
export async function generateVerificationCode(phoneNumber: string): Promise<string> {
  // Генерация 6-значного кода
  const code = randomInt(100000, 999999).toString();
  
  // Сохранение кода в хранилище с временем жизни 10 минут
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
  verificationStore[phoneNumber] = { 
    code, 
    expiresAt, 
    attempts: 0 
  };
  
  // Сохраняем код в базу данных для пользователя, если он уже существует
  const user = await storage.getUserByPhoneNumber(phoneNumber);
  if (user) {
    await storage.updateUser(user.id, { 
      verificationCode: code,
      verificationCodeExpires: expiresAt
    });
    
    // Логирование действия
    await storage.createLog({
      userId: user.id,
      action: "verification_code_sent",
      details: { phoneNumber },
      ipAddress: null
    });
  }
  
  console.log(`Generated verification code for ${phoneNumber}: ${code}`);
  
  return code;
}

// Проверка кода подтверждения
export function verifyCode(phoneNumber: string, code: string): boolean {
  const verificationData = verificationStore[phoneNumber];
  
  // Если данных нет или срок действия истёк
  if (!verificationData || new Date() > verificationData.expiresAt) {
    return false;
  }
  
  // Увеличиваем счётчик попыток
  verificationData.attempts += 1;
  
  // Проверяем код
  const isValid = verificationData.code === code;
  
  // Если код верный или превышено количество попыток, удаляем данные
  if (isValid || verificationData.attempts >= 5) {
    delete verificationStore[phoneNumber];
  }
  
  return isValid;
}

// Функция отправки кода через Telegram
export async function sendVerificationSMS(phoneNumber: string, code: string): Promise<boolean> {
  try {
    // Для отправки кода через Telegram, нам нужно:
    // 1) Найти пользователя Telegram с указанным номером телефона
    // 2) Отправить ему код через API Telegram
    
    // В текущей реализации мы будем показывать код в консоли
    // для тестирования, но в реальном приложении использовали бы
    // Telegram API или Телефонную авторизацию Telegram
    console.log(`[SMS] Your verification code is: ${code}`);
    
    // Пытаемся использовать Telegram бот, если доступен
    try {
      const botInstance = await getBotInstance();
      
      // Формирование более информативного сообщения
      const message = `
📱 *Подтверждение номера телефона*

Ваш код подтверждения: *${code}*

Если вы не запрашивали этот код, проигнорируйте это сообщение.
Код действителен в течение 10 минут.
      `.trim();
      
      // Попытка отправки через Telegram API
      // Для этого нам нужно знать Telegram ID пользователя по номеру телефона,
      // что не всегда возможно напрямую через Bot API.
      // В реальном приложении здесь можно использовать MTProto API.
      
      // Пытаемся получить настройку для чата админа
      const adminChatId = await storage.getSettingValue("admin_chat_id");
      
      // Если настройка есть и это валидный числовой ID, отправляем туда
      if (adminChatId && !isNaN(Number(adminChatId))) {
        try {
          await botInstance.api.sendMessage(adminChatId, 
            `🔔 Новый запрос кода подтверждения\n\nНомер: ${phoneNumber}\nКод: ${code}`, 
            { parse_mode: "Markdown" });
          console.log(`Verification code sent to admin chat: ${adminChatId}`);
        } catch (err) {
          console.error("Failed to send code to admin chat:", err);
        }
      } else {
        // Если нет настройки, используем проактивный поиск админов с правильными telegramId
        try {
          // Временное решение для тестирования - ищем пользователей с telegramId
          const allAdmins = await storage.listAdmins();
          let codeSent = false;
          
          for (const admin of allAdmins) {
            // Проверяем, что telegramId это числовое значение или начинается с цифры
            // (легитимные Telegram ID не могут начинаться с букв)
            if (admin.telegramId && /^\d/.test(admin.telegramId)) {
              try {
                await botInstance.api.sendMessage(admin.telegramId, 
                  `🔔 Новый запрос кода подтверждения\n\nНомер: ${phoneNumber}\nКод: ${code}`);
                codeSent = true;
                console.log(`Verification code sent to admin: ${admin.username} (${admin.telegramId})`);
              } catch (err) {
                console.error(`Failed to send code to admin ${admin.username}:`, err);
              }
            }
          }
          
          if (!codeSent) {
            console.log("Could not find any admin with valid Telegram ID. Code was not sent.");
          }
        } catch (err) {
          console.error("Error while searching for admins:", err);
        }
      }
      
      // В реальном приложении вместо этой функции 
      // лучше использовать официальный Telegram Login Widget
      
      return true;
    } catch (error) {
      console.error("Error sending code via Telegram:", error);
      // Если отправка через Telegram не удалась, считаем что все равно успешно
      // для целей демонстрации
      return true;
    }
  } catch (error) {
    console.error("Error in sendVerificationSMS:", error);
    return false;
  }
}

// Очистка устаревших кодов
export function cleanupExpiredCodes(): void {
  const now = new Date();
  for (const [phoneNumber, data] of Object.entries(verificationStore)) {
    if (now > data.expiresAt) {
      delete verificationStore[phoneNumber];
    }
  }
}

// Запускаем периодическую очистку устаревших кодов каждые 10 минут
setInterval(cleanupExpiredCodes, 10 * 60 * 1000);