import { db } from "./db";
import { settings } from "@shared/schema";
import { eq } from "drizzle-orm";
import * as crypto from "crypto";
import { sendVerificationTelegram } from "./phone-auth";

// Интерфейсы для типизации результатов
interface AuthResult {
  success: boolean;
  phoneCodeHash?: string;
  timeout?: number;
  error?: string;
}

interface VerifyResult {
  success: boolean;
  requireSignUp?: boolean;
  require2FA?: boolean;
  phoneCodeHash?: string;
  user?: {
    id: string;
    firstName: string;
    lastName: string;
    username: string;
    phone: string;
  };
  error?: string;
}

// Map для хранения информации о кодах подтверждения
const authCodes = new Map<string, { 
  phoneCodeHash: string; 
  expiresAt: Date; 
  code?: string; 
  attempts: number 
}>();

// Получение API ID и API Hash из настроек
async function getTelegramApiCredentials() {
  const [apiIdSetting, apiHashSetting] = await Promise.all([
    db.query.settings.findFirst({
      where: eq(settings.key, "telegram_api_id")
    }),
    db.query.settings.findFirst({
      where: eq(settings.key, "telegram_api_hash")
    })
  ]);

  const apiId = apiIdSetting?.value ? parseInt(apiIdSetting.value, 10) : 0;
  const apiHash = apiHashSetting?.value || "";

  return { apiId, apiHash };
}

// Отправка кода подтверждения через Telegram API
// В текущей имплементации используется отправка через бота
export async function sendAuthCode(phoneNumber: string): Promise<AuthResult> {
  try {
    // Проверяем наличие API_ID и API_HASH
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    if (!apiId || !apiHash) {
      console.log("Telegram API credentials not configured, falling back to bot delivery");
      // Если не настроены API_ID/API_HASH, используем отправку через бота
      return await sendAuthCodeViaBotFallback(phoneNumber);
    }

    // Генерируем случайный phoneCodeHash
    const phoneCodeHash = crypto.randomBytes(16).toString('hex');
    
    // Генерируем код верификации из 5 цифр
    const verificationCode = Math.floor(10000 + Math.random() * 90000).toString();
    
    console.log(`[DEBUG] Generated verification code for ${phoneNumber}: ${verificationCode}`);
    
    // Сохраняем информацию о коде
    authCodes.set(phoneNumber, {
      phoneCodeHash,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 минут
      code: verificationCode,
      attempts: 0
    });

    // TODO: В будущей реальной имплементации здесь будет код для отправки через MTProto API
    // А пока отправляем через бота
    const codeSent = await sendVerificationTelegram(phoneNumber, verificationCode);
    
    if (!codeSent) {
      return {
        success: false,
        error: "Failed to send verification code"
      };
    }

    return {
      success: true,
      phoneCodeHash,
      timeout: 120, // 2 минуты
    };
  } catch (error: any) {
    console.error("Error sending auth code:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка"
    };
  }
}

// Резервный способ отправки кода через бота
async function sendAuthCodeViaBotFallback(phoneNumber: string): Promise<AuthResult> {
  try {
    // Генерируем случайный phoneCodeHash
    const phoneCodeHash = crypto.randomBytes(16).toString('hex');
    
    // Генерируем код верификации из 6 цифр
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    
    console.log(`[DEBUG] Generated fallback verification code for ${phoneNumber}: ${verificationCode}`);
    
    // Сохраняем информацию о коде
    authCodes.set(phoneNumber, {
      phoneCodeHash,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 минут
      code: verificationCode,
      attempts: 0
    });

    // Отправляем код через бота
    const codeSent = await sendVerificationTelegram(phoneNumber, verificationCode);
    
    if (!codeSent) {
      return {
        success: false,
        error: "Failed to send verification code"
      };
    }

    return {
      success: true,
      phoneCodeHash,
      timeout: 600, // 10 минут
    };
  } catch (error: any) {
    console.error("Error sending auth code via bot:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при отправке кода"
    };
  }
}

// Верификация кода и вход в аккаунт
export async function verifyAuthCode(phoneNumber: string, code: string): Promise<VerifyResult> {
  try {
    const authData = authCodes.get(phoneNumber);
    
    if (!authData) {
      return { success: false, error: "Auth session expired or not found" };
    }

    if (authData.attempts >= 3) {
      authCodes.delete(phoneNumber);
      return { success: false, error: "Too many attempts" };
    }

    if (new Date() > authData.expiresAt) {
      authCodes.delete(phoneNumber);
      return { success: false, error: "Auth code expired" };
    }

    authData.attempts += 1;
    
    // Проверяем код
    if (authData.code && code === authData.code) {
      // Успешная верификация
      return { 
        success: true,
        user: {
          id: phoneNumber.replace(/[^0-9]/g, ''),
          firstName: "",
          lastName: "",
          username: "",
          phone: phoneNumber
        }
      };
    }

    // Если код неверный
    if (authData.attempts >= 3) {
      authCodes.delete(phoneNumber);
    }
    
    return { success: false, error: "Invalid code" };
  } catch (error: any) {
    console.error("Error verifying auth code:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при проверке кода"
    };
  }
}

// Регистрация нового пользователя, если требуется
export async function signUpNewUser(
  phoneNumber: string, 
  phoneCodeHash: string, 
  firstName: string, 
  lastName: string = ""
): Promise<VerifyResult> {
  try {
    // Проверяем, что у нас есть данные для этого номера телефона
    const authData = authCodes.get(phoneNumber);
    
    if (!authData || authData.phoneCodeHash !== phoneCodeHash) {
      return { success: false, error: "Invalid or expired session" };
    }
    
    return { 
      success: true, 
      user: {
        id: phoneNumber.replace(/[^0-9]/g, ''),
        firstName,
        lastName,
        username: "",
        phone: phoneNumber
      } 
    };
  } catch (error: any) {
    console.error("Error signing up:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при регистрации"
    };
  }
}

// Проверка 2FA пароля, если он требуется
export async function check2FAPassword(phoneNumber: string, password: string): Promise<VerifyResult> {
  try {
    // Проверяем, что у нас есть данные для этого номера телефона
    const authData = authCodes.get(phoneNumber);
    
    if (!authData) {
      return { success: false, error: "Invalid or expired session" };
    }
    
    // В текущей заглушке просто возвращаем успех при любом пароле
    return { 
      success: true, 
      user: {
        id: phoneNumber.replace(/[^0-9]/g, ''),
        firstName: "",
        lastName: "",
        username: "",
        phone: phoneNumber
      } 
    };
  } catch (error: any) {
    console.error("Error checking 2FA password:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при проверке пароля"
    };
  }
}

// Выход из аккаунта
export async function logoutTelegramUser(phoneNumber: string): Promise<{ success: boolean; error?: string }> {
  try {
    // Удаляем информацию о коде подтверждения
    authCodes.delete(phoneNumber);
    
    return { success: true };
  } catch (error: any) {
    console.error("Error logging out:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при выходе из аккаунта"
    };
  }
}

// Очистка устаревших сессий и кодов
export function cleanupExpiredSessions() {
  const now = new Date();
  
  // Очищаем устаревшие коды
  Array.from(authCodes.entries()).forEach(([phoneNumber, authData]) => {
    if (now > authData.expiresAt) {
      authCodes.delete(phoneNumber);
    }
  });
  
  // Устанавливаем интервал для регулярной очистки
  setInterval(() => {
    const now = new Date();
    Array.from(authCodes.entries()).forEach(([phoneNumber, authData]) => {
      if (now > authData.expiresAt) {
        authCodes.delete(phoneNumber);
      }
    });
  }, 5 * 60 * 1000); // Каждые 5 минут
}

// Инициализация при запуске сервера
export function initTelegramAuth() {
  cleanupExpiredSessions();
}