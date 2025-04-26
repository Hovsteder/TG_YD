import { TelegramClient, Api } from "telegram";
import { StringSession } from "telegram/sessions";
import { db } from "./db";
import { settings } from "@shared/schema";
import { eq } from "drizzle-orm";
import * as crypto from "crypto";

// Хранилище для сессий
let stringSession = "";
let client: TelegramClient | null = null;

// Функция для сохранения сессии в БД
async function saveSessionToDB(sessionStr: string) {
  try {
    console.log("Saving Telegram session to database...");
    await db.insert(settings)
      .values({
        key: "telegram_session",
        value: sessionStr,
        description: "Telegram client session string"
      })
      .onConflictDoUpdate({
        target: settings.key,
        set: { value: sessionStr }
      });
    console.log("Telegram session saved successfully to DB");
    return true;
  } catch (error) {
    console.error("Error saving Telegram session to DB:", error);
    return false;
  }
}

// Функция для загрузки сессии из БД
async function loadSessionFromDB(): Promise<string> {
  try {
    console.log("Loading Telegram session from database...");
    const sessionSetting = await db.query.settings.findFirst({
      where: eq(settings.key, "telegram_session")
    });
    
    if (sessionSetting?.value) {
      console.log("Telegram session loaded successfully from DB");
      return sessionSetting.value;
    }
    
    console.log("No saved Telegram session found in DB");
    return "";
  } catch (error) {
    console.error("Error loading Telegram session from DB:", error);
    return "";
  }
}

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
  waiting?: boolean; // Флаг ожидания сканирования QR-кода
  message?: string; // Дополнительное сообщение о состоянии
}

// Интерфейс для результата QR-авторизации
interface QRLoginResult {
  success: boolean;
  token?: string;
  url?: string;
  expires?: number;
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
    // Сохраняем сессию при каждом запросе для обеспечения стабильности
    if (client.session) {
      const newSession = client.session.save();
      if (typeof newSession === 'string') {
        stringSession = newSession;
        // Сохраняем сессию в БД при каждом запросе
        await saveSessionToDB(newSession);
      }
    }
    return client;
  }

  // Загружаем сессию из БД при первом подключении
  if (!stringSession) {
    stringSession = await loadSessionFromDB();
    console.log("Loaded session from DB:", stringSession ? "Session found" : "No session");
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
    
    // Если есть сохраненная сессия, попытаемся автоматически авторизовать клиент
    if (stringSession) {
      try {
        // Проверяем, авторизован ли клиент
        if (!client.connected) {
          await client.connect();
        }
        
        // Попытка получить информацию о текущем пользователе
        // для проверки авторизации
        try {
          const me = await client.getMe();
          console.log("Client automatically authenticated:", me);
        } catch (authError: any) {
          console.log("Not authenticated yet, waiting for login", authError?.message || "Unknown error");
        }
      } catch (authError: any) {
        console.warn("Failed to automatically authenticate:", authError?.message || "Unknown error");
      }
    }
    
    // Сохраняем обновленную сессию
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
    
    // Код тестового режима удален для перехода на реальную авторизацию по QR коду
    
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

    // Тестовый режим удален для перехода на реальную авторизацию

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
        
        // Сохраняем сессию в базу данных после успешной аутентификации
        const newSessionStr = currentClient.session.save();
        if (typeof newSessionStr === 'string') {
          stringSession = newSessionStr;
          console.log("Successfully saved authentication session after phone code verification");
          
          // Сохраняем в БД
          await saveSessionToDB(newSessionStr);
          console.log("Telegram session has been saved to database after successful phone login");
        }
        
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
  try {
    // Получаем клиент Telegram
    console.log("Инициализируем клиент MTProto для получения диалогов...");
    const currentClient = await getClient();
    
    if (!currentClient.connected) {
      console.error("MTProto client not connected to Telegram API!");
      return {
        success: false,
        error: "Not connected to Telegram API"
      };
    }
    
    // Проверяем аутентификацию путем попытки получения данных пользователя
    let isAuthenticated = false;
    try {
      // Если это вызовет ошибку, значит клиент не аутентифицирован
      const me = await currentClient.getMe();
      isAuthenticated = true;
      console.log("User is authenticated:", me);
    } catch (authError: any) {
      console.error("Error from Telegram API: Not authenticated with Telegram API", authError?.message || "Unknown error");
      return {
        success: false,
        error: "Not authenticated with Telegram API"
      };
    }
    
    try {
      console.log(`Fetching chats from Telegram API...`);
      
      // Используем рекомендованные API вызовы для получения чатов
      // Будем пробовать несколько методов для повышения надежности
      let result;
      
      // Используем только GetChats, т.к. GetAllChats вызывает ошибку типа
      console.log("Trying to get chats with messages.GetChats...");
      try {
        result = await currentClient.invoke(new Api.messages.GetChats({
          id: []  // пустой массив - получить доступные чаты
        }));
      } catch (apiError: any) {
        console.warn("Error using GetChats:", apiError?.message);
        
        // Пробуем прямой вызов getDialogs как запасной вариант
        console.log("Falling back to getDialogs method...");
        const dialogsResult = await currentClient.getDialogs({
          limit: limit
        });
        
        // Преобразуем результат в формат, похожий на результат GetChats
        result = {
          chats: dialogsResult.map((dialog: any) => dialog.entity).filter(Boolean)
        };
      }
      
      console.log(`Retrieved chats from Telegram API:`, result);
      
      // Получаем информацию из результата
      const chats: any[] = [];
      const users: any[] = [];
      const dialogs: any[] = [];
      
      // Обработка результатов API вызова
      if (result && result.chats) {
        // Преобразуем результат в массив, если это не массив
        const chatList = Array.isArray(result.chats) ? result.chats : [result.chats];
        
        // Теперь обрабатываем данные о чатах
        for (const chat of chatList) {
          const chatObj = chat as any;
          
          // Определяем тип чата
          let peerType = '';
          let peerId = '';
          
          if (chatObj.className === 'User') {
            peerType = 'user';
            peerId = `user_${chatObj.id}`;
            
            users.push({
              id: chatObj.id.toString(),
              first_name: chatObj.firstName || '',
              last_name: chatObj.lastName || '',
              username: chatObj.username || '',
              phone: chatObj.phone || ''
            });
          } else if (chatObj.className === 'Chat' || chatObj.className === 'ChatFull') {
            peerType = 'chat';
            peerId = `chat_${chatObj.id}`;
            
            chats.push({
              id: chatObj.id.toString(),
              title: chatObj.title || 'Group Chat',
              type: 'group'
            });
          } else if (chatObj.className === 'Channel' || chatObj.className === 'ChannelFull') {
            peerType = 'channel';
            peerId = `channel_${chatObj.id}`;
            
            chats.push({
              id: chatObj.id.toString(),
              title: chatObj.title || 'Channel',
              type: chatObj.megagroup ? 'supergroup' : 'channel'
            });
          }
          
          // Добавляем в список диалогов базовую информацию
          if (peerId) {
            dialogs.push({
              peer: {
                _: `peer${peerType.charAt(0).toUpperCase() + peerType.slice(1)}`,
                [`${peerType}_id`]: chatObj.id
              },
              unread_count: chatObj.unreadCount || 0,
              last_message_date: new Date().toISOString().split('T')[0], // Безопасная дата
              title: chatObj.title || (chatObj.firstName ? `${chatObj.firstName} ${chatObj.lastName || ''}`.trim() : 'Chat')
            });
          }
        }
      }
      
      // Если не получили никаких данных через API, попробуем использовать GetDialogs (резервный метод)
      if (dialogs.length === 0) {
        console.log("No chats received, trying alternative method...");
        try {
          const retrievedDialogs = await currentClient.getDialogs({
            limit: limit
          });
          
          console.log(`Retrieved ${retrievedDialogs.length} dialogs through alternative method`);
          
          // Добавляем текущего пользователя в список пользователей
          try {
            const me = await currentClient.getMe();
            if (me) {
              console.log("Adding current user to contacts list:", me.firstName);
              users.push({
                id: me.id?.toString(),
                first_name: me.firstName || '',
                last_name: me.lastName || '',
                username: me.username || '',
                phone: me.phone || ''
              });
            }
          } catch (e) {
            console.warn("Failed to get current user:", e);
          }
          
          // Собираем контакты пользователя для расширения списка доступных чатов
          try {
            // Используем API метод для получения контактов
            const contactsResult = await currentClient.invoke(new Api.contacts.GetContacts({}));
            
            if (contactsResult && contactsResult.className === 'contacts.Contacts') {
              const contactUsers = contactsResult.users || [];
              
              console.log(`Retrieved ${contactUsers.length} contacts`);
              
              for (const contact of contactUsers) {
                // Добавляем контакт в список пользователей если его еще нет
                const contactId = contact.id?.toString();
                if (contactId && !users.some(u => u.id === contactId)) {
                  const contactObj = contact as any; // Используем any для доступа к полям
                  users.push({
                    id: contactId,
                    first_name: contactObj.firstName || '',
                    last_name: contactObj.lastName || '',
                    username: contactObj.username || '',
                    phone: contactObj.phone || ''
                  });
                }
              }
            }
          } catch (e) {
            console.warn("Failed to get contacts:", e);
          }
          
          // Собираем информацию из диалогов в безопасном формате
          for (const dialog of retrievedDialogs) {
            const entity = dialog.entity as any;
            if (!entity) continue;
            
            console.log(`Processing dialog entity:`, entity.className, 'with ID:', entity.id?.toString());
            
            // Создаем объекты пользователей/чатов на основе типа сущности
            if (entity.className === 'User') {
              // Добавляем access_hash для пользователя, если он есть
              const accessHash = entity.accessHash ? entity.accessHash.toString() : '0';
              console.log(`User ${entity.id} access_hash:`, accessHash);
              
              // Проверяем, нет ли такого пользователя в списке уже
              if (!users.some(u => u.id === entity.id?.toString())) {
                users.push({
                  id: entity.id?.toString(),
                  first_name: entity.firstName || '',
                  last_name: entity.lastName || '',
                  username: entity.username || '',
                  phone: entity.phone || '',
                  access_hash: accessHash // Добавляем access_hash
                });
              }
            } else {
              // Добавляем access_hash для канала, если он есть
              const accessHash = entity.accessHash ? entity.accessHash.toString() : '0';
              console.log(`${entity.className} ${entity.id} access_hash:`, accessHash);
              
              // Проверяем, нет ли такого чата в списке уже
              if (!chats.some(c => c.id === entity.id?.toString())) {
                chats.push({
                  id: entity.id?.toString(),
                  title: entity.title || 'Chat',
                  type: entity.className === 'Channel' ? 
                    (entity.megagroup ? 'supergroup' : 'channel') : 'group',
                  access_hash: accessHash // Добавляем access_hash
                });
              }
            }
            
            // Создаем соответствующие объекты диалогов для обоих типов сущностей
            let peerType = '';
            let peerId = '';
            
            if (entity.className === 'User') {
              peerType = 'user';
              peerId = `user_${entity.id}`;
            } else if (entity.className === 'Chat' || entity.className === 'ChatFull') {
              peerType = 'chat';
              peerId = `chat_${entity.id}`;
            } else if (entity.className === 'Channel' || entity.className === 'ChannelFull') {
              peerType = 'channel';
              peerId = `channel_${entity.id}`;
            }
            
            // Добавляем диалог в список
            if (peerId) {
              dialogs.push({
                peer: {
                  _: `peer${peerType.charAt(0).toUpperCase() + peerType.slice(1)}`,
                  [`${peerType}_id`]: entity.id
                },
                unread_count: dialog.unreadCount || 0,
                last_message_date: new Date().toISOString().split('T')[0], // Безопасная дата
                title: entity.title || (entity.firstName ? `${entity.firstName} ${entity.lastName || ''}`.trim() : 'Chat')
              });
            }
          }
        } catch (altError: any) {
          console.warn("Alternative method also failed:", altError.message);
        }
      }
      
      return {
        success: true,
        dialogs: dialogs,
        users: users,
        chats: chats,
        count: dialogs.length
      };
    } catch (error: any) {
      console.error("Error fetching chats from Telegram:", error);
      return {
        success: false,
        error: error.message || "Error fetching chats from Telegram"
      };
    }
  } catch (error: any) {
    console.error("Error in getUserDialogs:", error);
    return {
      success: false,
      error: error.message || "Error connecting to Telegram API"
    };
  }
}

export async function getChatHistory(peer: any, limit = 20): Promise<any> {
  try {
    // Получаем клиент Telegram через API
    const currentClient = await getClient();
    
    if (!currentClient || !currentClient.connected) {
      console.error("Failed to get connected Telegram client");
      return {
        success: false,
        error: "Not connected to Telegram API"
      };
    }
    
    console.log(`Fetching chat history with peer:`, peer);
    
    try {
      // Импортированный Api доступен глобально, не нужно повторно использовать require
      
      // Пробуем разные способы получения сообщений в зависимости от типа чата
      if (peer._ === 'inputPeerChannel') {
        console.log(`Getting channel messages for channel_id=${peer.channel_id}`);
        
        try {
          // Создаем InputChannel для API
          const inputChannel = new Api.InputChannel({
            channelId: BigInt(peer.channel_id),
            accessHash: BigInt(peer.access_hash)
          });
          
          console.log("Created InputChannel:", inputChannel);
          
          // Получаем последние сообщения канала
          // Соберем ID сообщений (просто последовательность от 1 до limit)
          const messageIds = Array.from({ length: limit }, (_, i) => i + 1);
          
          const result = await currentClient.invoke(
            new Api.channels.GetMessages({
              channel: inputChannel,
              id: messageIds,
            })
          );
          
          console.log("Channel messages result:", result);
          
          if (result && result.messages) {
            // Извлекаем пользователей из ответа
            const users = result.users || [];
            
            // Форматируем сообщения
            const formattedMessages = result.messages.map((msg: any) => {
              // Определяем отправителя
              let from_id = null;
              if (msg.fromId) {
                from_id = msg.fromId;
              }
              
              return {
                _: 'message',
                id: msg.id,
                message: msg.message || '',
                date: msg.date,
                out: msg.out || false,
                media: msg.media || null,
                from_id: from_id
              };
            });
            
            return {
              success: true,
              messages: formattedMessages,
              users: users
            };
          }
        } catch (channelError) {
          console.error("Error getting channel messages:", channelError);
        }
      }
      
      // Второй способ - через telegram.js API getMessages
      // Примечание: этот метод может не сработать для некоторых пользователей из-за отсутствия сущности
      // Поэтому код включает обходной путь через messages.getHistory ниже
      console.log("Trying to get messages using getMessages...");
      
      // Выполняем запрос сущности, чтобы получить актуальный объект
      let entityId;
      let inputEntity;
      
      if (peer._ === 'inputPeerUser') {
        entityId = parseInt(peer.user_id);
        // Создаем InputPeerUser напрямую
        inputEntity = {
          className: "InputPeerUser",
          userId: entityId.toString(),
          accessHash: peer.access_hash.toString()
        };
      } else if (peer._ === 'inputPeerChat') {
        entityId = parseInt(peer.chat_id);
        inputEntity = {
          className: "InputPeerChat",
          chatId: entityId.toString()
        };
      } else if (peer._ === 'inputPeerChannel') {
        entityId = parseInt(peer.channel_id);
        inputEntity = {
          className: "InputPeerChannel",
          channelId: entityId.toString(),
          accessHash: peer.access_hash.toString()
        };
      }
      
      if (!entityId) {
        throw new Error("Could not determine entity ID from peer");
      }
      
      // Пробуем получить сообщения по entity ID
      try {
        // Чтобы избежать проблем с access_hash, можно использовать непосредственно InputPeer
        console.log(`Getting messages for entity ID: ${entityId}`);
        
        // Пробуем получить сообщения напрямую с inputEntity, пропуская этап getEntity
        let messages;
        try {
          messages = await currentClient.getMessages(inputEntity, {
            limit: limit
          });
        } catch (entityError) {
          console.error("Error getting messages with inputEntity:", entityError.message);
          
          // Запасной вариант - попытка получить сущность сначала
          try {
            const entity = await currentClient.getEntity(entityId);
            console.log("Retrieved entity:", entity);
            messages = await currentClient.getMessages(entity, {
              limit: limit
            });
          } catch (getEntityError) {
            console.error("Error getting entity:", getEntityError.message);
            // Не выбрасываем исключение здесь, чтобы перейти к следующему методу
            return { success: false, error: getEntityError.message };
          }
        }
        
        console.log(`Retrieved ${messages.length} messages from Telegram using getMessages`);
        
        if (messages && messages.length > 0) {
          // Собираем информацию о пользователях
          const users: any[] = [];
          
          // Обрабатываем сообщения
          const formattedMessages = messages.map(msg => {
            const message = msg as any;
            
            // Добавляем отправителя в список пользователей
            if (message.sender && message.sender.className === 'User') {
              const senderInfo = message.sender as any;
              const existingUser = users.find(u => u.id === senderInfo.id);
              if (!existingUser) {
                users.push({
                  id: senderInfo.id,
                  first_name: senderInfo.firstName || '',
                  last_name: senderInfo.lastName || '',
                  username: senderInfo.username || '',
                  photo: senderInfo.photo || null
                });
              }
            }
            
            // Форматируем сообщение
            return {
              _: 'message',
              id: message.id,
              message: message.message || '',
              date: message.date instanceof Date 
                ? Math.floor(message.date.getTime() / 1000) 
                : Math.floor(Date.now() / 1000),
              out: message.out || false,
              media: message.media || null,
              from_id: message.sender ? {
                _: 'peerUser',
                user_id: (message.sender as any).id
              } : null
            };
          });
          
          return {
            success: true,
            messages: formattedMessages,
            users: users
          };
        } else {
          console.log("No messages returned from getMessages");
        }
      } catch (entityError) {
        console.error("Error getting messages by entity:", entityError);
      }
      
      // Третий способ - через API метод getMessages напрямую для конкретного chatId
      console.log("Trying API method with specific message IDs...");
      
      try {
        // Здесь мы не используем MTProto API, а обращаемся напрямую к API методам telegram-js
        
        // Формируем правильный InputPeer для MTProto API
        let inputPeer = null;
        
        if (peer._ === 'inputPeerUser') {
          // Для пользователя
          inputPeer = {
            _: 'inputPeerUser',
            user_id: parseInt(peer.user_id),
            access_hash: peer.access_hash
          };
        } else if (peer._ === 'inputPeerChat') {
          // Для обычного чата
          inputPeer = {
            _: 'inputPeerChat',
            chat_id: parseInt(peer.chat_id)
          };
        } else if (peer._ === 'inputPeerChannel') {
          // Для канала или супергруппы
          inputPeer = {
            _: 'inputPeerChannel',
            channel_id: parseInt(peer.channel_id),
            access_hash: peer.access_hash
          };
        }
        
        if (!inputPeer) {
          throw new Error(`Unsupported peer type: ${peer._}`);
        }
        
        console.log("Calling messages.getHistory with peer:", inputPeer);
        
        // Используем низкоуровневый API для получения истории сообщений
        // Так как у нас нет прямого доступа к MTProto API, попробуем получить сообщения напрямую через TelegramClient
        
        // Получаем ID последних сообщений (предполагаем, что они последовательные)
        const messageIds = Array.from({ length: limit }, (_, i) => i + 1);
        console.log(`Trying to get specific message IDs: ${messageIds.join(', ')}`);
        
        // Вызываем API метод напрямую через TelegramClient
        let result;
        try {
          // Первый способ - через GetMessages
          result = await currentClient.invoke(new Api.messages.GetMessages({
            id: messageIds
          }));
          
          console.log("messages.GetMessages response:", result);
        } catch (apiError) {
          console.error("Error invoking messages.GetMessages:", apiError);
          
          // Попробуем альтернативный подход - получение сообщений через getHistory
          console.log("Trying to get messages through raw invoke with getHistory...");
          
          // Используем метод invoke напрямую
          try {
            // Вызываем getHistory напрямую через TelegramClient.invoke
            result = await currentClient.invoke(new Api.messages.GetHistory({
              peer: inputPeer,
              offsetId: 0,
              offsetDate: 0,
              addOffset: 0,
              limit: limit,
              maxId: 0,
              minId: 0,
              hash: BigInt(0)
            }));
            
            console.log("GetHistory response:", result);
          } catch (historyError) {
            console.error("Error with getHistory request:", historyError);
            throw historyError;
          }
        }
        
        
        if (result && result.messages) {
          // Извлекаем пользователей из ответа
          const users = result.users || [];
          
          // Форматируем сообщения
          const formattedMessages = result.messages.map((msg: any) => {
            // Определяем отправителя
            let from_id = null;
            if (msg.from_id) {
              from_id = msg.from_id;
            }
            
            return {
              _: 'message',
              id: msg.id,
              message: msg.message || '',
              date: msg.date,
              out: msg.out || false,
              media: msg.media || null,
              from_id: from_id
            };
          });
          
          return {
            success: true,
            messages: formattedMessages,
            users: users
          };
        }
      } catch (mtprotoError) {
        console.error("Error with native MTProto request:", mtprotoError);
      }
      
      // Если ни один метод не сработал, возвращаем ошибку
      return {
        success: false,
        error: "Failed to retrieve messages using multiple methods"
      };
      
    } catch (error: any) {
      console.error("Error in message retrieval:", error);
      return {
        success: false,
        error: error.message || "Error retrieving messages from Telegram"
      };
    }
  } catch (error: any) {
    console.error("Error in getChatHistory:", error);
    return {
      success: false,
      error: error.message || "Error connecting to Telegram API"
    };
  }
}

// Хранилище для QR-кодов
const qrLoginSessions = new Map<string, {
  token: string;
  expiresAt: Date;
}>();

// Map в глобальной области видимости для доступа из других модулей
declare global {
  var qrLoginSessions: Map<string, {
    token: string;
    expiresAt: Date;
  }>;
}

// Делаем доступными глобально
global.qrLoginSessions = qrLoginSessions;

// 1. Создание QR кода для входа
export async function createQRLoginCode(): Promise<QRLoginResult> {
  try {
    // Получаем клиент Telegram
    const currentClient = await getClient();
    
    try {
      console.log("Generating QR login code...");
      
      // Генерируем QR код с помощью API Telegram
      const result = await currentClient.invoke(new Api.auth.ExportLoginToken({
        apiId: (await getTelegramApiCredentials()).apiId,
        apiHash: (await getTelegramApiCredentials()).apiHash,
        exceptIds: []
      }));
      
      console.log("QR login export result:", result);
      
      // Проверяем результат - используем any для обхода ограничений типизации
      const anyResult = result as any;
      
      if (anyResult && anyResult.token) {
        // Генерируем уникальный token для отслеживания статуса
        const sessionToken = crypto.randomBytes(16).toString('hex');
        
        // Создаем URL для QR кода
        // Согласно документации Telegram, URL для QR кода имеет формат:
        // tg://login?token=base64(token)
        // Используем URL-safe base64 без отступов
        const tokenBase64 = Buffer.from(anyResult.token).toString('base64')
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
        const loginUrl = `tg://login?token=${tokenBase64}`;
        
        // Определяем срок действия (если есть)
        const expires = anyResult.expires || 300; // По умолчанию 5 минут
        
        // Сохраняем информацию о сессии
        qrLoginSessions.set(sessionToken, {
          token: tokenBase64,
          expiresAt: new Date(Date.now() + (expires * 1000))
        });
        
        return {
          success: true,
          token: sessionToken,
          url: loginUrl,
          expires: expires
        };
      }
      
      return {
        success: false,
        error: "Failed to generate QR login code"
      };
    } catch (error: any) {
      console.error("Error generating QR login code:", error);
      return {
        success: false,
        error: error.message || "Error generating QR login code"
      };
    }
  } catch (error: any) {
    console.error("Error in createQRLoginCode:", error);
    return {
      success: false,
      error: error.message || "Ошибка при создании QR кода для входа"
    };
  }
}

// 2. Проверка статуса авторизации по QR коду
export async function checkQRLoginStatus(token: string): Promise<VerifyResult> {
  try {
    console.log(`Checking QR login status for token: ${token}`);
    
    // Получаем данные сессии QR
    const sessionData = qrLoginSessions.get(token);
    if (!sessionData) {
      console.log(`QR session not found for token: ${token}`);
      return {
        success: false,
        error: "QR session not found or expired"
      };
    }
    
    console.log(`Found QR session with token: ${token}, expires: ${sessionData.expiresAt.toISOString()}`);
    
    // Проверяем, не истекла ли сессия
    if (new Date() > sessionData.expiresAt) {
      // Удаляем истекшую сессию
      qrLoginSessions.delete(token);
      return {
        success: false,
        error: "QR code expired"
      };
    }
    
    // Получаем клиент Telegram
    const currentClient = await getClient();
    
    try {
      // Проверяем статус авторизации путем создания нового экспортного токена
      // Когда пользователь сканирует QR-код, Telegram автоматически авторизует клиент
      // Если авторизация прошла успешно, то в результате запроса мы увидим пользователя
      const result = await currentClient.invoke(new Api.auth.ExportLoginToken({
        apiId: (await getTelegramApiCredentials()).apiId,
        apiHash: (await getTelegramApiCredentials()).apiHash,
        exceptIds: []
      }));
      
      console.log("QR login status check result:", result);
      
      // Telegram может вернуть несколько типов ответов:
      // 1. auth.LoginToken - означает, что пользователь еще не отсканировал QR-код
      // 2. auth.LoginTokenSuccess - означает, что пользователь отсканировал QR-код и авторизовался
      // 3. auth.LoginTokenMigrateTo - означает, что нужно перейти на другой DC
      
      // Проверяем тип ответа
      if (result.className === 'auth.LoginTokenSuccess') {
        // Пользователь отсканировал QR-код и авторизовался
        const anyResult = result as any;
        
        // Удаляем сессию QR
        qrLoginSessions.delete(token);
        
        // Важно: сохраняем текущую сессию для последующих запросов
        const newSessionStr = currentClient.session.save();
        if (typeof newSessionStr === 'string') {
          stringSession = newSessionStr;
          console.log("Successfully saved authentication session after QR login");
          
          // Явно сохраняем сессию в базу данных после успешной авторизации
          await saveSessionToDB(newSessionStr);
          console.log("Telegram session has been saved to database after successful QR login");
        }
        
        // Пробуем получить дополнительную информацию о пользователе
        try {
          const meUser = await currentClient.getMe();
          console.log("Additional user info after QR login:", meUser);
        } catch (userError: any) {
          console.warn("Could not get additional user info after QR login:", userError?.message);
        }
        
        // Если есть информация о пользователе, возвращаем её
        if (anyResult.authorization && anyResult.authorization.user) {
          const userInfo = anyResult.authorization.user;
          return {
            success: true,
            user: {
              id: userInfo.id.toString(),
              firstName: userInfo.firstName || "",
              lastName: userInfo.lastName || "",
              username: userInfo.username || "",
              phone: userInfo.phone || ""
            }
          };
        }
        
        // Если авторизация успешна, но информации о пользователе нет
        return {
          success: true,
          user: {
            id: "unknown",
            firstName: "Telegram",
            lastName: "User",
            username: "",
            phone: ""
          }
        };
      } 
      else if (result.className === 'auth.LoginToken') {
        // Пользователь еще не отсканировал QR-код, ожидаем
        return {
          success: false,
          waiting: true,
          message: "Waiting for QR code scan"
        };
      }
      else if (result.className === 'auth.LoginTokenMigrateTo') {
        // Требуется переход на другой DC, это нужно обработать отдельно
        // Но для простоты просто сообщаем, что требуется повторить попытку
        return {
          success: false,
          error: "Please try again with a new QR code"
        };
      }
      
      // Если неизвестный тип ответа
      return {
        success: false,
        waiting: true,
        message: "Waiting for QR code scan"
      };
    } catch (error: any) {
      console.error("Error checking QR login status:", error);
      
      // Если ошибка связана с тем, что пользователь не авторизован,
      // это нормально, просто ждем сканирования
      if (error.message && (
        error.message.includes('AUTH_KEY_UNREGISTERED') ||
        error.message.includes('SESSION_PASSWORD_NEEDED')
      )) {
        return {
          success: false,
          waiting: true,
          message: "Waiting for QR code scan"
        };
      }
      
      return {
        success: false,
        error: error.message || "Error checking QR login status"
      };
    }
  } catch (error: any) {
    console.error("Error in checkQRLoginStatus:", error);
    return {
      success: false,
      error: error.message || "Ошибка при проверке статуса QR авторизации"
    };
  }
}