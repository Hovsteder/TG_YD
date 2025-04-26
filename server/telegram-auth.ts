import { db } from "./db";
import { settings } from "@shared/schema";
import { eq } from "drizzle-orm";
import * as crypto from "crypto";
import { sendVerificationTelegram } from "./phone-auth";
import MTProto from '@mtproto/core';

// Глобальная переменная для хранения экземпляра MTProto API
let mtprotoClient: any = null;

// Объявляем глобальную переменную для доступа к authCodes из других модулей
declare global {
  var authCodes: Map<string, { 
    phoneCodeHash: string; 
    expiresAt: Date; 
    code?: string; 
    attempts: number 
  }>;
}

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

// Делаем доступным глобально
global.authCodes = authCodes;

// Инициализация MTProto клиента
async function initMTProtoClient() {
  try {
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    if (!apiId || !apiHash) {
      console.log("Telegram API credentials not configured, MTProto client will not be initialized");
      return null;
    }
    
    const mtproto = new MTProto({
      api_id: apiId,
      api_hash: apiHash,
      storageOptions: {
        path: './telegram-sessions'
      }
    });
    
    console.log("MTProto client initialized successfully");
    return mtproto;
  } catch (error) {
    console.error("Error initializing MTProto client:", error);
    return null;
  }
}

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

// Отправка кода подтверждения через официальный Telegram API
export async function sendAuthCode(phoneNumber: string): Promise<AuthResult> {
  try {
    // Проверяем наличие API_ID и API_HASH
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    if (!apiId || !apiHash) {
      console.log("Telegram API credentials not configured, falling back to bot delivery");
      // Если не настроены API_ID/API_HASH, используем отправку через бота
      return await sendAuthCodeViaBotFallback(phoneNumber);
    }

    // Инициализируем MTProto клиент, если еще не инициализирован
    if (!mtprotoClient) {
      mtprotoClient = await initMTProtoClient();
      
      if (!mtprotoClient) {
        console.log("Failed to initialize MTProto client, falling back to bot delivery");
        return await sendAuthCodeViaBotFallback(phoneNumber);
      }
    }

    try {
      // Отправляем запрос на код подтверждения через Telegram API
      console.log(`Sending auth.sendCode request to Telegram API for phone: ${phoneNumber}`);
      
      const result = await mtprotoClient.call('auth.sendCode', {
        phone_number: phoneNumber,
        api_id: apiId,
        api_hash: apiHash,
        settings: {
          _: 'codeSettings',
          allow_flashcall: false,
          current_number: true,
          allow_app_hash: true,
        }
      });
      
      console.log(`[DEBUG] auth.sendCode result:`, JSON.stringify(result));

      // Если получили ответ, сохраняем информацию о коде
      if (result && result.phone_code_hash) {
        // Генерируем код верификации для тестирования (в реальном сценарии придет через Telegram)
        // Это нужно только для тестирования, в реальном сценарии пользователь получит код в Telegram
        const verificationCode = Math.floor(10000 + Math.random() * 90000).toString();
        console.log(`[DEBUG] Testing verification code for ${phoneNumber}: ${verificationCode}`);
        
        authCodes.set(phoneNumber, {
          phoneCodeHash: result.phone_code_hash,
          expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 минут
          code: verificationCode, // Только для тестирования
          attempts: 0
        });
        
        return {
          success: true,
          phoneCodeHash: result.phone_code_hash,
          timeout: result.timeout || 300, // По умолчанию 5 минут
        };
      } else {
        throw new Error("Invalid response from Telegram API");
      }
    } catch (mtprotoError: any) {
      console.error("MTProto API error:", mtprotoError);
      
      // Если произошла ошибка с MTProto API, используем резервный метод
      console.log("Falling back to bot delivery due to MTProto API error");
      return await sendAuthCodeViaBotFallback(phoneNumber);
    }
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

// Верификация кода и вход в аккаунт через MTProto API
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

    // Сначала проверяем через MTProto API, если это возможно
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    if (apiId && apiHash && mtprotoClient) {
      try {
        console.log(`Attempting to sign in with phone ${phoneNumber} and code ${code}`);
        
        // Вызываем метод auth.signIn через MTProto API
        const signInResult = await mtprotoClient.call('auth.signIn', {
          phone_number: phoneNumber,
          phone_code_hash: authData.phoneCodeHash,
          phone_code: code
        });
        
        console.log(`[DEBUG] auth.signIn result:`, JSON.stringify(signInResult));
        
        // Если успешно авторизовались
        if (signInResult && signInResult.user) {
          // Очищаем данные авторизации
          authCodes.delete(phoneNumber);
          
          return {
            success: true,
            user: {
              id: signInResult.user.id.toString(),
              firstName: signInResult.user.first_name || "",
              lastName: signInResult.user.last_name || "",
              username: signInResult.user.username || "",
              phone: phoneNumber
            }
          };
        }
        
        // Если результат некорректный
        return { success: false, error: "Unexpected result from Telegram API" };
      } catch (mtprotoError: any) {
        console.error("MTProto API error during verification:", mtprotoError);
        
        // Если требуется регистрация нового пользователя
        if (mtprotoError.error_message === 'PHONE_NUMBER_UNOCCUPIED') {
          return { 
            success: false, 
            requireSignUp: true,
            phoneCodeHash: authData.phoneCodeHash,
            error: "Phone number not registered with Telegram"
          };
        }
        
        // Если требуется 2FA
        if (mtprotoError.error_message === 'SESSION_PASSWORD_NEEDED') {
          return {
            success: false,
            require2FA: true,
            phoneCodeHash: authData.phoneCodeHash,
            error: "Two-factor authentication required"
          };
        }
        
        // Для других ошибок используем локальную проверку (для отладки)
        console.log("Falling back to local code verification due to MTProto API error");
      }
    }
    
    // Резервный вариант: проверяем локально сохраненный код (для отладки)
    if (authData.code && code === authData.code) {
      // Очищаем данные авторизации
      authCodes.delete(phoneNumber);
      
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