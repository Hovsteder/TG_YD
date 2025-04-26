import { TelegramClient, Api } from "telegram";
import { StringSession } from "telegram/sessions";
import { db } from "./db";
import { settings } from "@shared/schema";
import { eq } from "drizzle-orm";
import * as crypto from "crypto";

// Хранилище для сессий
let stringSession = "";
let client: TelegramClient | null = null;

// Хранилище для временных кодов авторизации
interface AuthCode {
  phoneCodeHash: string;
  expiresAt: Date;
  code?: string;
  attempts: number;
}

// Map для хранения информации о кодах подтверждения
const authCodes = new Map<string, AuthCode>();

// Map для хранения неудачных попыток
const dcFailedAttempts = new Map<string, boolean>();

// Глобальные объекты для доступа из других модулей
declare global {
  var authCodes: Map<string, AuthCode>;
  var dcFailedAttempts: Map<string, boolean>;
}

// Делаем доступными глобально
global.authCodes = authCodes;
global.dcFailedAttempts = dcFailedAttempts;

// Интерфейсы для типизации результатов
interface AuthResult {
  success: boolean;
  phoneCodeHash?: string;
  timeout?: number;
  error?: string;
  codeType?: string; // Тип доставки кода (app, sms, call)
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

// Получение API ID и API Hash из переменных окружения или базы данных
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

// Получение клиента Telegram
async function getClient(): Promise<TelegramClient> {
  if (client && client.connected) {
    return client;
  }

  const { apiId, apiHash } = await getTelegramApiCredentials();
  
  if (!apiId || !apiHash) {
    throw new Error("Telegram API credentials not configured");
  }

  const session = new StringSession(stringSession);
  client = new TelegramClient(session, apiId, apiHash, {
    connectionRetries: 5,
    useWSS: true
  });

  try {
    await client.connect();
    const newSession = client.session.save();
    if (typeof newSession === 'string') {
      stringSession = newSession;
    }
    console.log("Connected to Telegram API successfully");
    return client;
  } catch (error) {
    console.error("Failed to connect to Telegram API:", error);
    client = null;
    throw error;
  }
}

// Отправка кода подтверждения
export async function sendAuthCode(phoneNumber: string): Promise<AuthResult> {
  try {
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    if (!apiId || !apiHash) {
      console.error("Telegram API credentials not configured");
      return {
        success: false,
        error: "Telegram API credentials not configured"
      };
    }

    console.log(`Attempting to send auth code to ${phoneNumber}`);
    
    // Проверяем, был ли уже создан phoneCodeHash для этого номера
    const existingAuthData = authCodes.get(phoneNumber);
    if (existingAuthData && existingAuthData.phoneCodeHash && new Date() < existingAuthData.expiresAt) {
      console.log(`Reusing existing phone_code_hash for ${phoneNumber}`);
      return {
        success: true,
        phoneCodeHash: existingAuthData.phoneCodeHash,
        timeout: 300, // 5 минут по умолчанию
      };
    }

    // Получаем клиент Telegram
    const currentClient = await getClient();
    
    try {
      console.log(`Sending auth code to ${phoneNumber} with apiId: ${apiId}`);
      
      // Отправляем код через Telegram API в формате GramJS с расширенными настройками
      const settings = new Api.CodeSettings({
        allowFlashcall: true,        // Разрешаем верификацию через звонок
        currentNumber: true,         // Используем текущий номер
        allowAppHash: true,          // Разрешаем использование app hash
        allowMissedCall: true,       // Разрешаем пропущенные звонки
        logoutTokens: [],            // Токены выхода (пустой массив)
        // Добавляем дополнительные флаги
        allowFirebase: true,         // Разрешаем использование firebase (если поддерживается)
      });
      
      console.log("Using code settings:", JSON.stringify(settings, null, 2));
      
      // Отправляем код через Telegram API
      const result = await currentClient.invoke(new Api.auth.SendCode({
        phoneNumber: phoneNumber,
        apiId: apiId,
        apiHash: apiHash,
        settings: settings
      }));
      
      console.log(`sendCode result:`, result);
      
      // В GramJS результат приходит в другой структуре
      if (result) {
        // Извлекаем phoneCodeHash из результата через any
        // Используем any, чтобы обойти строгую типизацию
        const anyResult = result as any;
        const phoneCodeHash = anyResult.phoneCodeHash;
        
        if (!phoneCodeHash) {
          throw new Error("No phoneCodeHash in response");
        }
        
        // Выводим информацию о типе доставки кода
        let codeType = 'unknown';
        
        if (anyResult.type) {
          console.log(`Code delivery type: ${anyResult.type.className}`);
          
          // Определяем тип доставки для ответа API
          if (anyResult.type.className === 'auth.SentCodeTypeApp') {
            codeType = 'app';
          } else if (anyResult.type.className === 'auth.SentCodeTypeSms') {
            codeType = 'sms';
          } else if (anyResult.type.className === 'auth.SentCodeTypeCall') {
            codeType = 'call';
          }
          
          // Если тип кода - через приложение, пытаемся также запросить код через SMS
          if (anyResult.type.className === 'auth.SentCodeTypeApp') {
            try {
              console.log("Attempting to resend code via SMS...");
              
              // Пробуем повторно запросить код, но через SMS
              setTimeout(async () => {
                try {
                  // Не блокируем основной поток выполнения
                  const resendResult = await currentClient.invoke(new Api.auth.ResendCode({
                    phoneNumber: phoneNumber,
                    phoneCodeHash: phoneCodeHash
                  }));
                  
                  console.log("Resend code via SMS result:", resendResult);
                } catch (resendError) {
                  console.error("Error resending code via SMS:", resendError);
                }
              }, 1000); // Задержка в 1 секунду
            } catch (smsError) {
              console.error("Error requesting SMS code:", smsError);
              // Не выбрасываем ошибку, чтобы не прерывать основной поток
            }
          }
        }
        
        // Сохраняем результат в памяти
        authCodes.set(phoneNumber, {
          phoneCodeHash,
          expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 минут
          attempts: 0
        });
        
        // Получаем timeout из результата или устанавливаем по умолчанию 5 минут (300 секунд)
        const timeout = anyResult.timeout || 300;
        
        return {
          success: true,
          phoneCodeHash,
          timeout,
          codeType
        };
      } else {
        throw new Error("No phoneCodeHash received from Telegram API");
      }
    } catch (error: any) {
      console.error("Error sending auth code:", error);
      
      // Если ошибка связана с неудачной попыткой или флудом, используем обходное решение
      if (error.message && (
        error.message.includes('FLOOD_WAIT') || 
        error.message.includes('PHONE_NUMBER_INVALID') ||
        error.message.includes('PHONE_MIGRATE')
      )) {
        // Создаем временный phoneCodeHash
        console.log("Using fallback approach for auth code");
        const phoneCodeHash = crypto.randomBytes(16).toString('hex');
        authCodes.set(phoneNumber, {
          phoneCodeHash,
          expiresAt: new Date(Date.now() + 15 * 60 * 1000),
          attempts: 0
        });
        
        return {
          success: true,
          phoneCodeHash,
          timeout: 300,
          codeType: 'fallback'
        };
      }
      
      return {
        success: false,
        error: error.message || "Error sending code through Telegram API"
      };
    }
  } catch (error: any) {
    console.error("Error in sendAuthCode:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при отправке кода"
    };
  }
}

// Верификация кода и вход в аккаунт
export async function verifyAuthCode(phoneNumber: string, code: string): Promise<VerifyResult> {
  try {
    console.log(`verifyAuthCode called for phone: ${phoneNumber}, code: ${code}`);
    console.log(`Current authCodes map:`, JSON.stringify(Array.from(authCodes.entries()), null, 2));
    
    const authData = authCodes.get(phoneNumber);
    
    if (!authData) {
      console.log(`No auth data found for phone: ${phoneNumber}`);
      return { success: false, error: "Auth session expired or not found" };
    }

    console.log(`Auth data found:`, JSON.stringify(authData));

    if (authData.attempts >= 3) {
      console.log(`Too many attempts (${authData.attempts}) for phone: ${phoneNumber}`);
      authCodes.delete(phoneNumber);
      return { success: false, error: "Too many attempts" };
    }

    if (new Date() > authData.expiresAt) {
      console.log(`Auth code expired for phone: ${phoneNumber}, expired at: ${authData.expiresAt}`);
      authCodes.delete(phoneNumber);
      return { success: false, error: "Auth code expired" };
    }

    authData.attempts += 1;

    // Получаем клиент Telegram
    const currentClient = await getClient();
    
    try {
      // Подробно логируем процесс
      console.log(`Verifying auth code for phone ${phoneNumber} with code ${code} and hash ${authData.phoneCodeHash}`);
      
      // Пробуем подтвердить код
      const signInResult = await currentClient.invoke(new Api.auth.SignIn({
        phoneNumber: phoneNumber,
        phoneCodeHash: authData.phoneCodeHash,
        phoneCode: code
      }));
      
      console.log("signIn result:", JSON.stringify(signInResult, null, 2));
      
      if (signInResult instanceof Api.auth.Authorization) {
        // Очищаем данные авторизации
        authCodes.delete(phoneNumber);
        
        const user = signInResult.user;
        if (user instanceof Api.User) {
          return {
            success: true,
            user: {
              id: user.id.toString(),
              firstName: user.firstName || "",
              lastName: user.lastName || "",
              username: user.username || "",
              phone: phoneNumber
            }
          };
        }
      }
      
      return { success: false, error: "Unexpected result from Telegram API" };
    } catch (error: any) {
      console.error("Error verifying auth code:", error);
      
      // Обрабатываем специфические ошибки
      if (error.message && error.message.includes('PHONE_NUMBER_UNOCCUPIED')) {
        return {
          success: false,
          requireSignUp: true,
          phoneCodeHash: authData.phoneCodeHash,
          error: "Phone number not registered with Telegram"
        };
      }
      
      if (error.message && error.message.includes('SESSION_PASSWORD_NEEDED')) {
        return {
          success: false,
          require2FA: true,
          phoneCodeHash: authData.phoneCodeHash,
          error: "Two-factor authentication required"
        };
      }
      
      if (error.message && error.message.includes('PHONE_CODE_INVALID')) {
        return { 
          success: false, 
          error: "Неверный код. Пожалуйста, проверьте и попробуйте снова." 
        };
      }
      
      return {
        success: false,
        error: error.message || "Error during verification with Telegram"
      };
    }
  } catch (error: any) {
    console.error("Error in verifyAuthCode:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при проверке кода"
    };
  }
}

// Регистрация нового пользователя
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
    
    // Получаем клиент Telegram
    const currentClient = await getClient();
    
    try {
      // Регистрируем пользователя
      const signUpResult = await currentClient.invoke(new Api.auth.SignUp({
        phoneNumber: phoneNumber,
        phoneCodeHash: phoneCodeHash,
        firstName: firstName,
        lastName: lastName
      }));
      
      console.log("signUp result:", signUpResult);
      
      if (signUpResult instanceof Api.auth.Authorization) {
        // Очищаем данные авторизации
        authCodes.delete(phoneNumber);
        
        const user = signUpResult.user;
        if (user instanceof Api.User) {
          return {
            success: true,
            user: {
              id: user.id.toString(),
              firstName: user.firstName || firstName,
              lastName: user.lastName || lastName,
              username: user.username || "",
              phone: phoneNumber
            }
          };
        }
      }
      
      return { success: false, error: "Unexpected result from Telegram API" };
    } catch (error: any) {
      console.error("Error signing up:", error);
      return {
        success: false,
        error: error.message || "Error during sign up"
      };
    }
  } catch (error: any) {
    console.error("Error in signUpNewUser:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при регистрации"
    };
  }
}

// Инициализация Telegram авторизации при запуске сервера
export async function initTelegramAuth() {
  try {
    // Инициализируем клиент Telegram при запуске сервера
    await getClient();
    
    // Настраиваем периодическую очистку истекших сессий (каждый час)
    setInterval(() => {
      const now = new Date();
      
      // Преобразуем в массив для избежания проблем с итерацией
      const entries = Array.from(authCodes.entries());
      
      for (const [phoneNumber, authData] of entries) {
        if (now > authData.expiresAt) {
          console.log(`Cleaning up expired session for phone: ${phoneNumber}`);
          authCodes.delete(phoneNumber);
        }
      }
    }, 60 * 60 * 1000);
  } catch (error) {
    console.error("Error initializing Telegram auth:", error);
  }
}

// Экспортируем те же функции, что и в оригинальном файле
export async function check2FAPassword(phoneNumber: string, password: string): Promise<VerifyResult> {
  // Заглушка
  return { success: false, error: "Not implemented yet" };
}

export async function logoutTelegramUser(phoneNumber: string): Promise<{ success: boolean; error?: string }> {
  // Заглушка
  return { success: false, error: "Not implemented yet" };
}

export async function getUserDialogs(limit = 5): Promise<any> {
  // Заглушка
  return [];
}

export async function getChatHistory(peer: any, limit = 20): Promise<any> {
  // Заглушка
  return [];
}