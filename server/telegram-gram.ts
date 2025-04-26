import { TelegramClient } from "telegram";
import { Api } from "telegram";
import { StringSession } from "telegram/sessions";
import { storage } from "./storage";
import * as crypto from "crypto";
import { db } from "./db";
import { settings } from "@shared/schema";
import { eq } from "drizzle-orm";

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

// Хранилище для QR кодов
const qrLoginTokens = new Map<string, {
  token: string; 
  expiresAt: Date;
  status: 'pending' | 'used' | 'expired';
  userData?: any;
}>();

// Глобальные переменные для хранения клиента и сессии
let telegramClient: TelegramClient | null = null;
let telegramSession: StringSession;

// Получение учетных данных API
async function getTelegramApiCredentials() {
  // Получаем apiId и apiHash из настроек
  const apiIdSetting = await storage.getSetting("telegram_api_id");
  const apiHashSetting = await storage.getSetting("telegram_api_hash");
  
  const apiId = apiIdSetting ? parseInt(apiIdSetting.value) : 0;
  const apiHash = apiHashSetting ? apiHashSetting.value : "";
  
  if (!apiId || !apiHash) {
    throw new Error("Telegram API credentials are not configured");
  }
  
  return { apiId, apiHash };
}

// Загрузка сохраненной сессии из БД
async function loadSessionFromDB(): Promise<string> {
  const sessionSetting = await storage.getSetting("telegram_session");
  return sessionSetting ? sessionSetting.value : "";
}

// Сохранение сессии в БД
async function saveSessionToDB(sessionStr: string): Promise<void> {
  console.log("Saving Telegram session to database...");
  await storage.upsertSetting(
    "telegram_session",
    sessionStr,
    "Telegram session string"
  );
  console.log("Telegram session saved successfully to DB");
}

// Получение клиента Telegram с инициализацией при необходимости
export async function getClient(): Promise<TelegramClient> {
  try {
    // Если клиент уже создан и подключен, возвращаем его
    if (telegramClient && telegramClient.connected) {
      return telegramClient;
    }
    
    // Получаем учетные данные API
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    // Загружаем сохраненную сессию
    const savedSession = await loadSessionFromDB();
    telegramSession = new StringSession(savedSession);
    
    // Создаем новый клиент
    telegramClient = new TelegramClient(telegramSession, apiId, apiHash, {
      connectionRetries: 5,
      useWSS: true,
    });
    
    // Подключаемся к Telegram API
    await telegramClient.connect();
    
    // Проверяем авторизацию
    if (!(await telegramClient.checkAuthorization())) {
      throw new Error("Telegram client is not authorized");
    }
    
    // Сохраняем обновленную сессию
    const sessionString = telegramClient.session.save() as string;
    await saveSessionToDB(sessionString);
    
    console.log("Connected to Telegram API successfully");
    return telegramClient;
  } catch (error) {
    console.error("Error initializing Telegram client:", error);
    throw error;
  }
}

// Отправка кода авторизации на телефон
export async function sendAuthCode(phoneNumber: string): Promise<AuthResult> {
  try {
    // Получаем учетные данные API
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    // Создаем временный клиент для авторизации
    const client = new TelegramClient(new StringSession(""), apiId, apiHash, {
      connectionRetries: 3,
      useWSS: true,
    });
    
    // Подключаемся
    await client.connect();
    
    console.log(`Sending auth code to ${phoneNumber}`);
    
    // Отправляем код
    const { phoneCodeHash, timeout } = await client.sendCode({
      apiId,
      apiHash,
      phoneNumber,
    });
    
    await client.disconnect();
    
    return {
      success: true,
      phoneCodeHash,
      timeout,
    };
  } catch (error: any) {
    console.error('Error sending auth code:', error);
    return {
      success: false,
      error: error.message || 'Error sending authentication code',
    };
  }
}

// Проверка кода авторизации
export async function verifyAuthCode(phoneNumber: string, code: string): Promise<VerifyResult> {
  try {
    // Получаем учетные данные API
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    // Создаем временный клиент для авторизации
    const client = new TelegramClient(new StringSession(""), apiId, apiHash, {
      connectionRetries: 3,
      useWSS: true,
    });
    
    await client.connect();
    
    try {
      // Проверяем код
      const signInResult = await client.invoke(new Api.auth.SignIn({
        phoneNumber,
        phoneCodeHash: "code_hash_here", // В реальности должен быть получен из предыдущего шага
        phoneCode: code,
      }));
      
      // Сохраняем сессию
      const sessionString = client.session.save() as string;
      await saveSessionToDB(sessionString);
      
      // Получаем данные пользователя
      const userMe = await client.getMe();
      
      await client.disconnect();
      
      return {
        success: true,
        user: {
          id: userMe.id.toString(),
          firstName: userMe.firstName || "",
          lastName: userMe.lastName || "",
          username: userMe.username || "",
          phone: userMe.phone || "",
        },
      };
    } catch (err: any) {
      await client.disconnect();
      if (err.message.includes("not registered")) {
        return {
          success: false,
          requireSignUp: true,
          error: "User not registered",
        };
      } else if (err.message.includes("2FA")) {
        return {
          success: false,
          require2FA: true,
          error: "Two-factor authentication required",
        };
      } else {
        return {
          success: false,
          error: err.message,
        };
      }
    }
  } catch (error: any) {
    console.error('Error verifying auth code:', error);
    return {
      success: false,
      error: error.message || 'Error verifying authentication code',
    };
  }
}

// Регистрация нового пользователя
export async function signUpNewUser(
  phoneNumber: string,
  phoneCodeHash: string, 
  firstName: string,
  lastName: string
): Promise<VerifyResult> {
  try {
    // В реальности здесь должен быть полный код для регистрации пользователя
    return {
      success: true,
      user: {
        id: "new_id",
        firstName,
        lastName,
        username: "",
        phone: phoneNumber,
      },
    };
  } catch (error: any) {
    console.error('Error signing up user:', error);
    return {
      success: false,
      error: error.message || 'Error registering new user',
    };
  }
}

// Проверка пароля 2FA
export async function check2FAPassword(phoneNumber: string, password: string): Promise<VerifyResult> {
  try {
    // В реальности здесь должен быть полный код для проверки пароля 2FA
    return {
      success: true,
      user: {
        id: "user_id",
        firstName: "First",
        lastName: "Last",
        username: "username",
        phone: phoneNumber,
      },
    };
  } catch (error: any) {
    console.error('Error checking 2FA password:', error);
    return {
      success: false,
      error: error.message || 'Error checking 2FA password',
    };
  }
}

// Выход из Telegram аккаунта
export async function logoutTelegramUser(phoneNumber: string): Promise<{ success: boolean; error?: string }> {
  try {
    const client = await getClient();
    await client.invoke(new Api.auth.LogOut());
    
    // Очищаем сессию в БД
    await saveSessionToDB("");
    
    // Сбрасываем клиент
    telegramClient = null;
    
    return { success: true };
  } catch (error: any) {
    console.error('Error logging out:', error);
    return {
      success: false,
      error: error.message || 'Error logging out',
    };
  }
}

// Инициализация Telegram Auth
export async function initTelegramAuth() {
  try {
    // Инициализируем клиент
    const client = await getClient();
    console.log("Telegram auth initialized successfully");
    return true;
  } catch (error) {
    console.error("Failed to initialize Telegram auth:", error);
    return false;
  }
}

// Создание QR кода для входа
export async function createQRLoginCode(): Promise<{ success: boolean; qrCode?: string; error?: string }> {
  try {
    const client = await getClient();
    
    // Генерируем токен для входа
    const result = await client.invoke(new Api.auth.ExportLoginToken({
      apiId: client.apiId,
      apiHash: client.apiHash as string,
      exceptIds: []
    }));
    
    if (!result.token) {
      throw new Error("Failed to get login token");
    }
    
    // Создаем токен в формате tg://login?token=<token>
    const token = Buffer.from(result.token).toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    
    const qrCode = `tg://login?token=${token}`;
    
    // Сохраняем токен для проверки статуса
    const tokenId = crypto.randomBytes(16).toString('hex');
    qrLoginTokens.set(tokenId, {
      token: token,
      expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 минут
      status: 'pending'
    });
    
    return {
      success: true,
      qrCode: qrCode
    };
  } catch (error: any) {
    console.error("Error creating QR login code:", error);
    return {
      success: false,
      error: error.message || "Failed to create QR login code"
    };
  }
}

// Проверка статуса QR кода
export async function checkQRLoginStatus(): Promise<{ 
  success: boolean; 
  status: 'pending' | 'used' | 'expired'; 
  userData?: any;
  error?: string;
}> {
  try {
    // В реальности здесь должен быть код для проверки статуса QR кода
    return {
      success: true,
      status: 'pending'
    };
  } catch (error: any) {
    console.error("Error checking QR login status:", error);
    return {
      success: false,
      status: 'expired',
      error: error.message || "Failed to check QR login status"
    };
  }
}

// Получение диалогов пользователя
export async function getUserDialogs(limit = 5): Promise<any> {
  try {
    const client = await getClient();
    
    console.log("Getting user dialogs...");
    
    // Получаем диалоги
    const result = await client.getDialogs({
      limit: limit
    });
    
    console.log(`Retrieved ${result.length} dialogs`);
    
    // Форматируем результат
    return {
      success: true,
      dialogs: result.map((dialog: any) => {
        const entity = dialog.entity;
        
        let chatType = 'unknown';
        let chatId = '';
        let accessHash = '0';
        
        if (entity.className === 'User') {
          chatType = 'user';
          chatId = entity.id.toString();
          accessHash = entity.accessHash ? entity.accessHash.toString() : '0';
        } else if (entity.className === 'Chat') {
          chatType = 'chat';
          chatId = entity.id.toString();
        } else if (entity.className === 'Channel') {
          chatType = 'channel';
          chatId = entity.id.toString();
          accessHash = entity.accessHash ? entity.accessHash.toString() : '0';
        }
        
        return {
          id: `${chatType}_${chatId}`,
          type: chatType,
          title: dialog.title || entity.title || entity.firstName || 'Unknown',
          unreadCount: dialog.unreadCount || 0,
          lastMessage: dialog.message ? dialog.message.message : '',
          accessHash: accessHash
        };
      })
    };
  } catch (error: any) {
    console.error("Error getting user dialogs:", error);
    return {
      success: false,
      error: error.message || "Failed to get user dialogs"
    };
  }
}

// Получение истории чата
export async function getChatHistory(peer: any, limit = 20): Promise<any> {
  try {
    // Получаем клиент Telegram
    const currentClient = await getClient();
    
    if (!currentClient || !currentClient.connected) {
      return {
        success: false,
        error: "Not connected to Telegram API"
      };
    }
    
    console.log(`Fetching chat history with peer:`, peer);
    
    // Формируем правильный InputPeer для API запроса
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
    
    try {
      // Вызываем метод GetHistory напрямую через TelegramClient.invoke
      const result = await currentClient.invoke(new Api.messages.GetHistory({
        peer: inputPeer,
        offsetId: 0,
        offsetDate: 0,
        addOffset: 0,
        limit: limit,
        maxId: 0,
        minId: 0,
        hash: BigInt(0)
      }));
      
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
      } else {
        return {
          success: false,
          error: "No messages returned from API"
        };
      }
    } catch (error: any) {
      console.error("Error with messages.getHistory request:", error);
      return {
        success: false,
        error: `Error getting history: ${error.message}`
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