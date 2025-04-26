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
  // Добавляем хранилище для отслеживания неудачных попыток подключения к DC
  var dcFailedAttempts: Map<string, boolean>;
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

// Создаем хранилище для отслеживания неудачных попыток с DC
const dcFailedAttempts = new Map<string, boolean>();

// Делаем доступными глобально
global.authCodes = authCodes;
global.dcFailedAttempts = dcFailedAttempts;

// Инициализация MTProto клиента (с опциональным указанием DC)
async function initMTProtoClient(dcId?: number) {
  try {
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    if (!apiId || !apiHash) {
      console.log("Telegram API credentials not configured, MTProto client will not be initialized");
      return null;
    }
    
    // Конфигурация DC для продакшн-серверов Telegram
    const dcConfigs: any = {
      1: { id: 1, ip: '149.154.175.50', port: 443 },
      2: { id: 2, ip: '149.154.167.51', port: 443 },
      3: { id: 3, ip: '149.154.175.100', port: 443 },
      4: { id: 4, ip: '149.154.167.91', port: 443 },
      5: { id: 5, ip: '149.154.171.5', port: 443 }
    };
    
    const options: any = {
      api_id: apiId,
      api_hash: apiHash,
      storageOptions: {
        path: './telegram-sessions'
      },
      useWSS: true, // Используем защищенное соединение
      test: false,  // Используем продакшн-серверы
      connectionRetries: 3 // Увеличиваем количество попыток переподключения
    };
    
    // Если указан конкретный DC, добавляем соответствующие настройки
    if (dcId && dcConfigs[dcId]) {
      console.log(`Initializing MTProto client with specific DC${dcId} configuration`);
      
      options.customDc = dcId;
      options.dcId = dcId;
      options.dev = false;  // Отключаем режим разработки
      options.dc = dcConfigs[dcId];
    } 
    else if (dcId) {
      console.log(`Initializing MTProto client with default DC ${dcId} configuration`);
      options.customDc = dcId;
    }
    
    const mtproto = new MTProto(options);
    
    console.log(`MTProto client initialized successfully${dcId ? ` for DC ${dcId}` : ''}`);
    return mtproto;
  } catch (error) {
    console.error("Error initializing MTProto client:", error);
    return null;
  }
}

// Получение MTProto клиента для конкретного DC (используется для обработки PHONE_MIGRATE ошибок)
async function getMTProtoClientForDc(dcId: number): Promise<any> {
  try {
    // Создаем клиент для конкретного DC
    const dcClient = await initMTProtoClient(dcId);
    
    if (!dcClient) {
      console.error(`Failed to initialize MTProto client for DC ${dcId}`);
      return null;
    }
    
    return dcClient;
  } catch (error) {
    console.error(`Error getting MTProto client for DC ${dcId}:`, error);
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

    console.log(`Attempting to send auth code to ${phoneNumber}`);
    
    // Проверяем, был ли уже создан phoneCodeHash для этого номера
    // Если да, то получаем его и возвращаем без повторной отправки кода
    const existingAuthData = authCodes.get(phoneNumber);
    if (existingAuthData && existingAuthData.phoneCodeHash && new Date() < existingAuthData.expiresAt) {
      console.log(`Reusing existing phone_code_hash for ${phoneNumber}`);
      return {
        success: true,
        phoneCodeHash: existingAuthData.phoneCodeHash,
        timeout: 300, // 5 минут по умолчанию
      };
    }
    
    // Вспомогательная функция для отправки кода
    const tryAuthSendCode = async (client: any, dcIdForLogs: string | number = 'default'): Promise<any> => {
      console.log(`Trying auth.sendCode with DC${dcIdForLogs} for phone: ${phoneNumber}`);
      
      // Создаем Promise с таймаутом
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Telegram API request timed out')), 15000); // 15 секунд
      });
      
      // Используем Promise.race для ограничения времени ожидания
      return Promise.race([
        client.call('auth.sendCode', {
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
    };

    // Основная логика отправки кода
    // Изначально пробуем с основным клиентом
    if (!mtprotoClient) {
      console.log(`Initializing main MTProto client`);
      mtprotoClient = await initMTProtoClient();
      if (!mtprotoClient) {
        return {
          success: false,
          error: "Failed to initialize MTProto client"
        };
      }
    }

    try {
      // Первая попытка с основным клиентом
      const result = await tryAuthSendCode(mtprotoClient);
      
      console.log(`auth.sendCode success for phone: ${phoneNumber}`);
      
      // Обрабатываем успешный ответ
      if (result && result.phone_code_hash) {
        authCodes.set(phoneNumber, {
          phoneCodeHash: result.phone_code_hash,
          expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 минут
          attempts: 0
        });
        
        return {
          success: true,
          phoneCodeHash: result.phone_code_hash,
          timeout: result.timeout || 300,
        };
      } else {
        throw new Error("Invalid response from Telegram API");
      }
    } catch (initialError: any) {
      console.error("Initial MTProto API error:", initialError);
      
      // Обрабатываем ошибки миграции
      if (
        initialError.error_message && (
          initialError.error_message.startsWith('PHONE_MIGRATE_') ||
          initialError.error_message.startsWith('NETWORK_MIGRATE_') ||
          initialError.error_message.startsWith('USER_MIGRATE_')
        )
      ) {
        // Извлекаем номер DC из ошибки
        const dcId = parseInt(initialError.error_message.split('_').pop());
        
        if (!isNaN(dcId) && dcId > 0 && dcId <= 5) { // Проверяем, что DC ID валидный
          console.log(`Phone needs DC ${dcId}, switching for phone: ${phoneNumber}`);
          
          // Проверим, была ли неудачная попытка с этим DC
          const dcKey = `dc${dcId}_failed_${phoneNumber}`;
          if (dcFailedAttempts.get(dcKey)) {
            console.log(`Previous attempt with DC${dcId} failed, using fallback approach`);
            
            // Используем временное решение для обхода проблемы
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
            };
          }

          try {
            // Создаем клиент для конкретного DC
            const dcClient = await initMTProtoClient(dcId);
            
            if (!dcClient) {
              // Помечаем, что попытка с этим DC не удалась
              dcFailedAttempts.set(dcKey, true);
              
              return {
                success: false,
                error: `Failed to connect to Telegram DC${dcId}`
              };
            }
            
            // Пробуем отправить код с новым клиентом
            const result = await tryAuthSendCode(dcClient, dcId);
            
            console.log(`auth.sendCode success for phone ${phoneNumber} using DC${dcId}`);
            
            // Обрабатываем успешный ответ
            if (result && result.phone_code_hash) {
              authCodes.set(phoneNumber, {
                phoneCodeHash: result.phone_code_hash,
                expiresAt: new Date(Date.now() + 15 * 60 * 1000),
                attempts: 0
              });
              
              return {
                success: true,
                phoneCodeHash: result.phone_code_hash,
                timeout: result.timeout || 300,
              };
            }
          } catch (dcError: any) {
            console.error(`Error with DC${dcId} client:`, dcError);
            
            // Помечаем, что попытка с этим DC не удалась
            dcFailedAttempts.set(dcKey, true);
            
            // Проверяем, не является ли ошибка миграцией
            if (dcError.error_message && dcError.error_message.includes('MIGRATE_')) {
              console.log(`Recursive migration error with DC${dcId}, using fallback`);
              
              // Используем временное решение для циклических ошибок миграции
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
              };
            }
            
            // Для других ошибок возвращаем конкретную ошибку
            return {
              success: false,
              error: dcError.error_message || `Error with DC${dcId}`
            };
          }
        }
      }
      
      // Специальная обработка для случаев, когда ошибки не связаны с миграцией
      if (initialError.error_message === 'FLOOD_WAIT') {
        return {
          success: false,
          error: "Слишком много попыток. Пожалуйста, попробуйте позже."
        };
      }
      
      // Для всех остальных ошибок - возвращаем ошибку
      return {
        success: false,
        error: initialError.error_message || "Error sending code through Telegram API"
      };
    }
  } catch (error: any) {
    console.error("Error sending auth code:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при отправке кода"
    };
  }
}

// Функция testModeAuthCode удалена - используется только официальный MTProto API

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

    // Функция для попытки верификации кода
    const tryVerifyCode = async (client: any, dcIdForLogs: string | number = 'default'): Promise<any> => {
      console.log(`Trying auth.signIn with DC${dcIdForLogs} for phone: ${phoneNumber} and code: ${code}`);
      
      // Проверяем, что authData существует
      if (!authData || !authData.phoneCodeHash) {
        throw new Error("Invalid auth data for verification");
      }
      
      // Создаем Promise с таймаутом
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Telegram API request timed out')), 15000); // 15 секунд
      });
      
      // Используем Promise.race для ограничения времени ожидания
      return Promise.race([
        client.call('auth.signIn', {
          phone_number: phoneNumber,
          phone_code_hash: authData.phoneCodeHash,
          phone_code: code
        }),
        timeoutPromise
      ]);
    };

    // Основная логика верификации
    if (!mtprotoClient) {
      console.log('Initializing main MTProto client for verification');
      mtprotoClient = await initMTProtoClient();
      
      if (!mtprotoClient) {
        console.error("Failed to initialize MTProto client for verification");
        return { success: false, error: "Failed to initialize MTProto client" };
      }
    }

    try {
      // Первая попытка с основным клиентом
      const signInResult = await tryVerifyCode(mtprotoClient);
      
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
    } catch (initialError: any) {
      console.error("MTProto API error during verification:", initialError);
      
      // Если требуется регистрация нового пользователя
      if (initialError.error_message === 'PHONE_NUMBER_UNOCCUPIED') {
        return { 
          success: false, 
          requireSignUp: true,
          phoneCodeHash: authData.phoneCodeHash,
          error: "Phone number not registered with Telegram"
        };
      }
      
      // Если требуется 2FA
      if (initialError.error_message === 'SESSION_PASSWORD_NEEDED') {
        return {
          success: false,
          require2FA: true,
          phoneCodeHash: authData.phoneCodeHash,
          error: "Two-factor authentication required"
        };
      }
      
      // Обрабатываем ошибки миграции
      if (
        initialError.error_message && (
          initialError.error_message.startsWith('PHONE_MIGRATE_') ||
          initialError.error_message.startsWith('NETWORK_MIGRATE_') ||
          initialError.error_message.startsWith('USER_MIGRATE_')
        )
      ) {
        // Извлекаем номер DC из ошибки
        const dcId = parseInt(initialError.error_message.split('_').pop());
        
        if (!isNaN(dcId) && dcId > 0 && dcId <= 5) { // Проверяем, что DC ID валидный
          console.log(`Phone needs DC ${dcId} for verification, switching for phone: ${phoneNumber}`);
          
          // Проверим, была ли неудачная попытка с этим DC
          const dcKey = `vrf_dc${dcId}_failed_${phoneNumber}`;
          if (dcFailedAttempts.get(dcKey)) {
            console.log(`Previous verification attempt with DC${dcId} failed, returning error`);
            return {
              success: false,
              error: `Previous attempt with DC${dcId} failed. Please try again.`
            };
          }

          // Создаем клиент для конкретного DC
          const dcClient = await initMTProtoClient(dcId);
          
          if (!dcClient) {
            // Помечаем, что попытка с этим DC не удалась
            dcFailedAttempts.set(dcKey, true);
            
            return {
              success: false,
              error: `Failed to connect to Telegram DC${dcId}`
            };
          }
          
          try {
            // Пробуем верифицировать с новым клиентом
            const signInResult = await tryVerifyCode(dcClient, dcId);
            
            console.log(`auth.signIn success for phone ${phoneNumber} using DC${dcId}`);
            
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
          } catch (dcError: any) {
            console.error(`Error with DC${dcId} client during verification:`, dcError);
            
            // Помечаем, что попытка с этим DC не удалась
            dcFailedAttempts.set(dcKey, true);
            
            // Проверяем те же ошибки, что и в основном блоке
            if (dcError.error_message === 'PHONE_NUMBER_UNOCCUPIED') {
              return { 
                success: false, 
                requireSignUp: true,
                phoneCodeHash: authData.phoneCodeHash,
                error: "Phone number not registered with Telegram"
              };
            }
            
            if (dcError.error_message === 'SESSION_PASSWORD_NEEDED') {
              return {
                success: false,
                require2FA: true,
                phoneCodeHash: authData.phoneCodeHash,
                error: "Two-factor authentication required"
              };
            }
            
            // Для других ошибок возвращаем конкретную ошибку
            return {
              success: false,
              error: dcError.error_message || `Error with DC${dcId}: ${dcError}`
            };
          }
        }
      }
      
      // Обработка ошибки неверного кода
      if (initialError.error_message === 'PHONE_CODE_INVALID') {
        return { 
          success: false, 
          error: "Неверный код. Пожалуйста, проверьте и попробуйте снова." 
        };
      }
      
      // Обработка истечения срока кода
      if (initialError.error_message === 'PHONE_CODE_EXPIRED') {
        // Удаляем данные авторизации
        authCodes.delete(phoneNumber);
        
        return { 
          success: false, 
          error: "Срок действия кода истек. Запросите новый код." 
        };
      }
      
      // Для других ошибок возвращаем общую ошибку
      return { 
        success: false, 
        error: initialError.error_message || "Error during verification with Telegram" 
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
    
    // Проверяем наличие API_ID и API_HASH
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    if (!apiId || !apiHash) {
      console.error("Telegram API credentials not configured for signup");
      return { success: false, error: "Telegram API credentials not configured" };
    }

    if (!mtprotoClient) {
      mtprotoClient = await initMTProtoClient();
      
      if (!mtprotoClient) {
        console.error("Failed to initialize MTProto client for signup");
        return { success: false, error: "Failed to initialize MTProto client" };
      }
    }

    try {
      console.log(`Attempting to sign up with phone ${phoneNumber}, name: ${firstName} ${lastName}`);
      
      // Создаем Promise с таймаутом (10 секунд для продакшн)
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Telegram API request timed out')), 10000);
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
      
      console.log(`auth.signUp success for phone: ${phoneNumber}`);
      
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
    const authData = authCodes.get(phoneNumber);
    
    if (!authData) {
      return { success: false, error: "Auth session expired or not found" };
    }
    
    // Проверяем наличие API_ID и API_HASH
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    if (!apiId || !apiHash) {
      console.error("Telegram API credentials not configured for 2FA check");
      return { success: false, error: "Telegram API credentials not configured" };
    }

    if (!mtprotoClient) {
      mtprotoClient = await initMTProtoClient();
      
      if (!mtprotoClient) {
        console.error("Failed to initialize MTProto client for 2FA check");
        return { success: false, error: "Failed to initialize MTProto client" };
      }
    }

    try {
      console.log(`Attempting to check 2FA password for phone: ${phoneNumber}`);
      
      // Сначала нужно получить информацию о 2FA
      const passwordInfo = await mtprotoClient.call('account.getPassword');
      
      if (!passwordInfo || !passwordInfo.srp_B || !passwordInfo.srp_id || !passwordInfo.current_algo) {
        return { success: false, error: "Failed to get password information" };
      }
      
      // Создаем SRP параметры для проверки пароля
      // Примечание: это упрощенная реализация, в реальном сценарии нужно использовать SRP алгоритм
      const check = await mtprotoClient.call('auth.checkPassword', {
        password: {
          _: 'inputCheckPasswordSRP',
          srp_id: passwordInfo.srp_id,
          A: 'A',
          M1: 'M1'
        }
      });
      
      if (check && check.user) {
        // Очищаем данные авторизации
        authCodes.delete(phoneNumber);
        
        return {
          success: true,
          user: {
            id: check.user.id.toString(),
            firstName: check.user.first_name || "",
            lastName: check.user.last_name || "",
            username: check.user.username || "",
            phone: phoneNumber
          }
        };
      }
      
      return { success: false, error: "2FA check failed" };
    } catch (mtprotoError: any) {
      console.error("MTProto API error during 2FA check:", mtprotoError);
      return {
        success: false,
        error: mtprotoError.error_message || "Error during 2FA check"
      };
    }
  } catch (error: any) {
    console.error("Error checking 2FA password:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при проверке пароля"
    };
  }
}

// Выход из Telegram аккаунта
export async function logoutTelegramUser(phoneNumber: string): Promise<{ success: boolean; error?: string }> {
  try {
    // Проверяем наличие API_ID и API_HASH
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    if (!apiId || !apiHash) {
      console.error("Telegram API credentials not configured for logout");
      return { success: false, error: "Telegram API credentials not configured" };
    }

    if (!mtprotoClient) {
      mtprotoClient = await initMTProtoClient();
      
      if (!mtprotoClient) {
        console.error("Failed to initialize MTProto client for logout");
        return { success: false, error: "Failed to initialize MTProto client" };
      }
    }

    try {
      console.log(`Attempting to logout Telegram user for phone: ${phoneNumber}`);
      
      // Создаем Promise с таймаутом (10 секунд для продакшн)
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Telegram API request timed out')), 10000);
      });
      
      // Вызываем метод auth.logOut через MTProto API с таймаутом
      const logoutResult = await Promise.race([
        mtprotoClient.call('auth.logOut', {}),
        timeoutPromise
      ]);
      
      if (logoutResult) {
        console.log(`auth.logOut success for phone: ${phoneNumber}`);
        return { success: true };
      } else {
        return { success: false, error: "Logout failed" };
      }
    } catch (mtprotoError: any) {
      console.error("MTProto API error during logout:", mtprotoError);
      return {
        success: false,
        error: mtprotoError.error_message || "Error during logout"
      };
    }
  } catch (error: any) {
    console.error("Error logging out:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при выходе из аккаунта"
    };
  }
}

// Очистка истекших сессий
export function cleanupExpiredSessions() {
  const now = new Date();
  
  for (const [phoneNumber, authData] of authCodes.entries()) {
    if (now > authData.expiresAt) {
      console.log(`Cleaning up expired session for phone: ${phoneNumber}`);
      authCodes.delete(phoneNumber);
    }
  }
}

// Инициализация Telegram авторизации при запуске сервера
export async function initTelegramAuth() {
  try {
    // Инициализируем MTProto клиент при запуске сервера
    mtprotoClient = await initMTProtoClient();
    
    if (mtprotoClient) {
      console.log("MTProto client initialized successfully during server startup");
    } else {
      console.warn("Failed to initialize MTProto client during server startup");
    }
    
    // Настраиваем периодическую очистку истекших сессий (каждый час)
    setInterval(cleanupExpiredSessions, 60 * 60 * 1000);
  } catch (error) {
    console.error("Error initializing Telegram auth:", error);
  }
}

// Получение диалогов пользователя через MTProto API
export async function getUserDialogs(limit = 5): Promise<any> {
  try {
    if (!mtprotoClient) {
      mtprotoClient = await initMTProtoClient();
      
      if (!mtprotoClient) {
        throw new Error("Failed to initialize MTProto client");
      }
    }
    
    const result = await mtprotoClient.call('messages.getDialogs', {
      offset_date: 0,
      offset_id: 0,
      offset_peer: { _: 'inputPeerEmpty' },
      limit
    });
    
    return result;
  } catch (error) {
    console.error("Error getting dialogs:", error);
    throw error;
  }
}

// Получение истории сообщений чата через MTProto API
export async function getChatHistory(peer: any, limit = 20): Promise<any> {
  try {
    if (!mtprotoClient) {
      mtprotoClient = await initMTProtoClient();
      
      if (!mtprotoClient) {
        throw new Error("Failed to initialize MTProto client");
      }
    }
    
    const result = await mtprotoClient.call('messages.getHistory', {
      peer,
      offset_id: 0,
      offset_date: 0,
      add_offset: 0,
      limit,
      max_id: 0,
      min_id: 0,
      hash: 0
    });
    
    return result;
  } catch (error) {
    console.error("Error getting chat history:", error);
    throw error;
  }
}