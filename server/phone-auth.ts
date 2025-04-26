import { storage } from "./storage";
import { randomInt } from "crypto";

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

// Функция отправки SMS с кодом (заглушка)
export async function sendVerificationSMS(phoneNumber: string, code: string): Promise<boolean> {
  // В реальном приложении здесь был бы код для отправки SMS через Twilio, MessageBird и т.д.
  console.log(`[SMS] Your verification code is: ${code}`);
  
  // В учебных целях считаем, что SMS успешно отправлено
  return true;
  
  // Пример интеграции с Twilio:
  /*
  try {
    const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
    await client.messages.create({
      body: `Your verification code is: ${code}`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phoneNumber
    });
    return true;
  } catch (error) {
    console.error("Error sending SMS:", error);
    return false;
  }
  */
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