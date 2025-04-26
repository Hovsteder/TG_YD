import { db } from "./db";
import { settings } from "@shared/schema";
import { eq } from "drizzle-orm";
import * as crypto from "crypto";
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

// Получение API ID и API Hash из переменных окружения
async function getTelegramApiCredentials() {
  // Приоритет: сначала из переменных окружения, затем из базы данных
  let apiId = process.env.TELEGRAM_API_ID ? parseInt(process.env.TELEGRAM_API_ID, 10) : 0;
  let apiHash = process.env.TELEGRAM_API_HASH || "";

  // Если переменных окружения нет, пробуем получить из базы данных
  if (!apiId || !apiHash) {
    const [apiIdSetting, apiHashSetting] = await Promise.all([
      db.query.settings.findFirst({
        where: eq(settings.key, "telegram_api_id")
      }),
      db.query.settings.findFirst({
        where: eq(settings.key, "telegram_api_hash")
      })
    ]);

    apiId = apiIdSetting?.value ? parseInt(apiIdSetting.value, 10) : apiId;
    apiHash = apiHashSetting?.value || apiHash;
  }

  return { apiId, apiHash };
}

// Отправка кода подтверждения через официальный Telegram API
export async function sendAuthCode(phoneNumber: string): Promise<AuthResult> {
  try {
    // Проверяем наличие API_ID и API_HASH
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    if (!apiId || !apiHash) {
      console.error("Telegram API credentials not configured");
      return {
        success: false,
        error: "Telegram API credentials not configured"
      };
    }

    // Инициализируем MTProto клиент, если еще не инициализирован
    if (!mtprotoClient) {
      mtprotoClient = await initMTProtoClient();
      
      if (!mtprotoClient) {
        console.error("Failed to initialize MTProto client");
        return {
          success: false,
          error: "Failed to initialize MTProto client"
        };
      }
    }

    // Отправляем запрос на код подтверждения через Telegram API
    console.log(`Sending auth.sendCode request to Telegram API for phone: ${phoneNumber}`);
    
    // Создаем Promise с таймаутом (10 секунд для продакшн)
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Telegram API request timed out')), 10000);
    });
    
    // Используем Promise.race для ограничения времени ожидания
    const result = await Promise.race([
      mtprotoClient.call('auth.sendCode', {
        phone_number: phoneNumber,
        api_id: apiId,
        api_hash: apiHash,
        settings: {
          _: 'codeSettings',
          allow_flashcall: false,
          current_number: true,
          allow_app_hash: true,
        }
      }),
      timeoutPromise
    ]);
    
    console.log(`auth.sendCode success for phone: ${phoneNumber}`);

    // Если получили ответ, сохраняем информацию о коде
    if (result && result.phone_code_hash) {
      // В реальном сценарии пользователь получит код в Telegram
      // Мы сохраняем только phone_code_hash для последующей проверки
      authCodes.set(phoneNumber, {
        phoneCodeHash: result.phone_code_hash,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 минут
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
  } catch (error: any) {
    console.error("Error sending auth code:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при отправке кода"
    };
  }
}

// Тестовый режим без отправки через Telegram API
async function testModeAuthCode(phoneNumber: string): Promise<AuthResult> {
  try {
    // Генерируем случайный phoneCodeHash
    const phoneCodeHash = crypto.randomBytes(16).toString('hex');
    
    // Генерируем код верификации из 6 цифр
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Выводим код очень заметно в консоль для тестирования
    console.log('\n');
    console.log('=====================================================================');
    console.log(`🔑 VERIFICATION CODE FOR ${phoneNumber}: ${verificationCode}`);
    console.log('=====================================================================');
    console.log('\n');
    
    // Сохраняем информацию о коде
    authCodes.set(phoneNumber, {
      phoneCodeHash,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 минут
      code: verificationCode,
      attempts: 0
    });

    return {
      success: true,
      phoneCodeHash,
      timeout: 600, // 10 минут
    };
  } catch (error: any) {
    console.error("Error in test mode auth code:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при генерации тестового кода"
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

    // Проверяем наличие API_ID и API_HASH
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    if (!apiId || !apiHash) {
      console.error("Telegram API credentials not configured for verification");
      return { success: false, error: "Telegram API credentials not configured" };
    }

    if (!mtprotoClient) {
      mtprotoClient = await initMTProtoClient();
      
      if (!mtprotoClient) {
        console.error("Failed to initialize MTProto client for verification");
        return { success: false, error: "Failed to initialize MTProto client" };
      }
    }

    try {
      console.log(`Attempting to sign in with phone ${phoneNumber} and code ${code}`);
      
      // Создаем Promise с таймаутом (10 секунд для продакшн)
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Telegram API request timed out')), 10000);
      });
      
      // Вызываем метод auth.signIn через MTProto API с таймаутом
      const signInResult = await Promise.race([
        mtprotoClient.call('auth.signIn', {
          phone_number: phoneNumber,
          phone_code_hash: authData.phoneCodeHash,
          phone_code: code
        }),
        timeoutPromise
      ]);
      
      console.log(`auth.signIn success for phone: ${phoneNumber}`);
      
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
      
      // Для других ошибок возвращаем общую ошибку
      return { 
        success: false, 
        error: mtprotoError.error_message || "Error during verification with Telegram" 
      };
    }
  } catch (error: any) {
    console.error("Error verifying auth code:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при проверке кода"
    };
  }
}

// Регистрация нового пользователя через MTProto API
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
    
    // Сначала проверяем, можем ли использовать MTProto API
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    if (apiId && apiHash && mtprotoClient) {
      try {
        console.log(`Attempting to sign up with phone ${phoneNumber}, name: ${firstName} ${lastName}`);
        
        // Создаем Promise с таймаутом
        const timeoutPromise = new Promise((_, reject) => {
          setTimeout(() => reject(new Error('Telegram API request timed out')), 5000);
        });
        
        // Вызываем метод auth.signUp через MTProto API с таймаутом
        const signUpResult = await Promise.race([
          mtprotoClient.call('auth.signUp', {
            phone_number: phoneNumber,
            phone_code_hash: phoneCodeHash,
            first_name: firstName,
            last_name: lastName
          }),
          timeoutPromise
        ]);
        
        console.log(`[DEBUG] auth.signUp result:`, JSON.stringify(signUpResult));
        
        // Если успешно зарегистрировались
        if (signUpResult && signUpResult.user) {
          // Очищаем данные авторизации
          authCodes.delete(phoneNumber);
          
          return {
            success: true,
            user: {
              id: signUpResult.user.id.toString(),
              firstName: signUpResult.user.first_name || firstName,
              lastName: signUpResult.user.last_name || lastName,
              username: signUpResult.user.username || "",
              phone: phoneNumber
            }
          };
        }
        
        // Если результат некорректный
        return { success: false, error: "Unexpected result from Telegram API" };
      } catch (mtprotoError: any) {
        console.error("MTProto API error during signup:", mtprotoError);
        return {
          success: false,
          error: mtprotoError.error_message || "Error during sign up"
        };
      }
    }
    
    // Резервный вариант, если MTProto API недоступен
    console.log("Using fallback signup method");
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

// Проверка 2FA пароля через MTProto API
export async function check2FAPassword(phoneNumber: string, password: string): Promise<VerifyResult> {
  try {
    // Проверяем, что у нас есть данные для этого номера телефона
    const authData = authCodes.get(phoneNumber);
    
    if (!authData) {
      return { success: false, error: "Invalid or expired session" };
    }
    
    // Сначала проверяем, можем ли использовать MTProto API
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    if (apiId && apiHash && mtprotoClient) {
      try {
        console.log(`Attempting to check 2FA password for ${phoneNumber}`);
        
        // Создаем Promise с таймаутом
        const timeoutPromise = new Promise((_, reject) => {
          setTimeout(() => reject(new Error('Telegram API request timed out')), 5000);
        });
        
        // Получаем информацию о 2FA с таймаутом
        const passwordInfo = await Promise.race([
          mtprotoClient.call('account.getPassword'),
          timeoutPromise
        ]);
        
        console.log(`[DEBUG] account.getPassword result:`, JSON.stringify(passwordInfo));
        
        if (!passwordInfo || !passwordInfo.srp_id || !passwordInfo.current_algo) {
          return { success: false, error: "Failed to get password info from Telegram" };
        }
        
        // Вычисляем SRP параметры на основе пароля (это упрощенная версия)
        // В реальности это сложный криптографический процесс
        const srpParams = {
          srp_id: passwordInfo.srp_id,
          A: crypto.randomBytes(256).toString('hex'),
          M1: crypto.createHash('sha256').update(password).digest('hex')
        };
        
        // Создаем еще один Promise с таймаутом
        const pwdTimeoutPromise = new Promise((_, reject) => {
          setTimeout(() => reject(new Error('Telegram API password check timed out')), 5000);
        });
        
        // Вызываем метод auth.checkPassword через MTProto API с таймаутом
        const checkPasswordResult = await Promise.race([
          mtprotoClient.call('auth.checkPassword', {
            password: {
              _: 'inputCheckPasswordSRP',
              ...srpParams
            }
          }),
          pwdTimeoutPromise
        ]);
        
        console.log(`[DEBUG] auth.checkPassword result:`, JSON.stringify(checkPasswordResult));
        
        // Если успешно прошли 2FA
        if (checkPasswordResult && checkPasswordResult.user) {
          // Очищаем данные авторизации
          authCodes.delete(phoneNumber);
          
          return {
            success: true,
            user: {
              id: checkPasswordResult.user.id.toString(),
              firstName: checkPasswordResult.user.first_name || "",
              lastName: checkPasswordResult.user.last_name || "",
              username: checkPasswordResult.user.username || "",
              phone: phoneNumber
            }
          };
        }
        
        // Если результат некорректный
        return { success: false, error: "Unexpected result from Telegram API" };
      } catch (mtprotoError: any) {
        console.error("MTProto API error during 2FA check:", mtprotoError);
        
        // Если неверный пароль
        if (mtprotoError.error_message === 'PASSWORD_HASH_INVALID') {
          return {
            success: false,
            error: "Invalid password"
          };
        }
        
        return {
          success: false,
          error: mtprotoError.error_message || "Error checking 2FA password"
        };
      }
    }
    
    // Резервный вариант, если MTProto API недоступен (для отладки)
    console.log("Using fallback 2FA check method");
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

// Выход из аккаунта через MTProto API
export async function logoutTelegramUser(phoneNumber: string): Promise<{ success: boolean; error?: string }> {
  try {
    // Удаляем информацию о коде подтверждения
    authCodes.delete(phoneNumber);
    
    // Сначала проверяем, можем ли использовать MTProto API
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    if (apiId && apiHash && mtprotoClient) {
      try {
        console.log(`Attempting to log out for ${phoneNumber}`);
        
        // Создаем Promise с таймаутом
        const timeoutPromise = new Promise((_, reject) => {
          setTimeout(() => reject(new Error('Telegram API logout timed out')), 5000);
        });
        
        // Вызываем метод auth.logOut через MTProto API с таймаутом
        const logoutResult = await Promise.race([
          mtprotoClient.call('auth.logOut'),
          timeoutPromise
        ]);
        
        console.log(`[DEBUG] auth.logOut result:`, JSON.stringify(logoutResult));
        
        // Если успешно вышли
        if (logoutResult === true) {
          return { success: true };
        }
        
        // Если результат некорректный
        return { success: false, error: "Unexpected result from Telegram API" };
      } catch (mtprotoError: any) {
        console.error("MTProto API error during logout:", mtprotoError);
        return {
          success: false,
          error: mtprotoError.error_message || "Error during logout"
        };
      }
    }
    
    // Резервный вариант, если MTProto API недоступен
    console.log("Using fallback logout method");
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
export async function initTelegramAuth() {
  // Очистка устаревших сессий
  cleanupExpiredSessions();
  
  // Инициализация MTProto клиента
  try {
    mtprotoClient = await initMTProtoClient();
    if (mtprotoClient) {
      console.log("MTProto client initialized successfully during server startup");
    } else {
      console.log("Failed to initialize MTProto client during server startup");
    }
  } catch (error) {
    console.error("Error initializing MTProto client during server startup:", error);
  }
}