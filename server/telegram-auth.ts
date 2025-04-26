import { Api, TelegramClient } from "telegram";
import { StringSession } from "telegram/sessions";
import { db } from "./db";
import { settings } from "@shared/schema";
import { eq } from "drizzle-orm";
import * as crypto from "crypto";

// Map для хранения клиентов Telegram, ключ - phoneNumber
const clientSessions = new Map<string, { client: TelegramClient; session: StringSession }>();
// Map для хранения информации о кодах подтверждения
const authCodes = new Map<string, { phoneCodeHash: string; expiresAt: Date; code?: string; attempts: number }>();

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

// Получение клиента Telegram для номера телефона
async function getTelegramClient(phoneNumber: string) {
  let clientData = clientSessions.get(phoneNumber);

  if (!clientData) {
    const { apiId, apiHash } = await getTelegramApiCredentials();
    
    if (!apiId || !apiHash) {
      throw new Error("Telegram API credentials not configured");
    }

    const session = new StringSession("");
    const client = new TelegramClient(session, apiId, apiHash, {
      connectionRetries: 3,
      deviceModel: "Telegram Web App",
      systemVersion: "1.0",
      appVersion: "1.0",
      langCode: "en"
    });

    clientData = { client, session };
    clientSessions.set(phoneNumber, clientData);
  }

  return clientData;
}

// Отправка кода подтверждения через Telegram API
export async function sendAuthCode(phoneNumber: string) {
  try {
    const { client } = await getTelegramClient(phoneNumber);
    
    // Подключаемся к Telegram
    if (!client.connected) {
      await client.connect();
    }

    // Отправляем запрос на код
    const result = await client.sendCode({
      phoneNumber,
      settings: {
        allowFlashcall: false,
        currentNumber: true,
        allowAppHash: true,
        allowMissedCall: false,
        allowFirebase: false,
      }
    });

    // Сохраняем phoneCodeHash для последующего использования
    authCodes.set(phoneNumber, {
      phoneCodeHash: result.phoneCodeHash,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 минут
      attempts: 0
    });

    return {
      success: true,
      phoneCodeHash: result.phoneCodeHash,
      timeout: result.timeout || 120,
      type: result.type
    };
  } catch (error) {
    console.error("Error sending auth code:", error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Верификация кода и вход в аккаунт
export async function verifyAuthCode(phoneNumber: string, code: string) {
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
    
    const { client } = await getTelegramClient(phoneNumber);
    
    // Подключаемся к Telegram если нужно
    if (!client.connected) {
      await client.connect();
    }

    // Пытаемся войти с полученным кодом
    try {
      const signInResult = await client.invoke(new Api.auth.SignIn({
        phoneNumber,
        phoneCodeHash: authData.phoneCodeHash,
        phoneCode: code
      }));

      if (signInResult instanceof Api.auth.AuthorizationSignUpRequired) {
        // Требуется регистрация нового пользователя
        return { 
          success: true, 
          requireSignUp: true,
          phoneCodeHash: authData.phoneCodeHash
        };
      }

      // Успешный вход
      const user = signInResult.user;
      return { 
        success: true, 
        user: {
          id: user.id.toString(),
          firstName: user.firstName || "",
          lastName: user.lastName || "",
          username: user.username || "",
          phone: user.phone || "",
          accessHash: user.accessHash?.toString() || "",
        } 
      };
    } catch (error) {
      if (error.message.includes("SESSION_PASSWORD_NEEDED")) {
        // Требуется 2FA пароль
        return { 
          success: true, 
          require2FA: true,
          phoneCodeHash: authData.phoneCodeHash
        };
      }
      throw error;
    }
  } catch (error) {
    console.error("Error verifying auth code:", error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Регистрация нового пользователя, если требуется
export async function signUpNewUser(phoneNumber: string, phoneCodeHash: string, firstName: string, lastName: string = "") {
  try {
    const { client } = await getTelegramClient(phoneNumber);
    
    // Подключаемся к Telegram если нужно
    if (!client.connected) {
      await client.connect();
    }

    const signUpResult = await client.invoke(new Api.auth.SignUp({
      phoneNumber,
      phoneCodeHash,
      firstName,
      lastName
    }));

    if (!signUpResult.user) {
      return { success: false, error: "Failed to sign up" };
    }

    const user = signUpResult.user;
    return { 
      success: true, 
      user: {
        id: user.id.toString(),
        firstName: user.firstName || "",
        lastName: user.lastName || "",
        username: user.username || "",
        phone: user.phone || "",
        accessHash: user.accessHash?.toString() || "",
      } 
    };
  } catch (error) {
    console.error("Error signing up:", error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Проверка 2FA пароля, если он требуется
export async function check2FAPassword(phoneNumber: string, password: string) {
  try {
    const { client } = await getTelegramClient(phoneNumber);
    
    // Подключаемся к Telegram если нужно
    if (!client.connected) {
      await client.connect();
    }

    try {
      const passwordResult = await client.invoke(new Api.auth.CheckPassword({
        password: await computePasswordCheck(client, password)
      }));

      const user = passwordResult.user;
      return { 
        success: true, 
        user: {
          id: user.id.toString(),
          firstName: user.firstName || "",
          lastName: user.lastName || "",
          username: user.username || "",
          phone: user.phone || "",
          accessHash: user.accessHash?.toString() || "",
        } 
      };
    } catch (error) {
      if (error.message.includes("PASSWORD_HASH_INVALID")) {
        return { success: false, error: "Invalid password" };
      }
      throw error;
    }
  } catch (error) {
    console.error("Error checking 2FA password:", error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Хелпер для вычисления правильного хэша пароля для 2FA
async function computePasswordCheck(client: TelegramClient, password: string) {
  const passwordSrpResult = await client.invoke(new Api.account.GetPassword());
  
  const { srpB, srpId, currentAlgo, srp_B, srp_id } = passwordSrpResult;
  const algo = currentAlgo as any;
  
  // Получаем параметры SRP
  const g = BigInt(algo.g);
  const p = BigInt(algo.p.toString("hex"), 16);
  
  // Создаем SRP клиент
  const bytesToBigInt = (bytes: Buffer) => BigInt(`0x${bytes.toString("hex")}`);
  const random = (size: number) => crypto.randomBytes(size);
  
  // Генерируем приватный ключ
  const a = bytesToBigInt(random(256));
  
  // Вычисляем A = g^a % p
  const A = g ** a % p;

  // Вычисляем хэш пароля
  const passwordBytes = Buffer.from(password, "utf8");
  const salt1 = algo.salt1;
  const salt2 = algo.salt2;
  
  const hash1 = crypto.createHash("sha256");
  hash1.update(salt1);
  hash1.update(passwordBytes);
  hash1.update(salt1);
  const hash1Result = hash1.digest();
  
  const hash2 = crypto.createHash("sha256");
  hash2.update(salt2);
  hash2.update(hash1Result);
  hash2.update(salt2);
  const hash2Result = hash2.digest();
  
  const hash3 = crypto.createHash("sha256");
  hash3.update(salt1);
  hash3.update(hash2Result);
  hash3.update(salt1);
  const hash3Result = hash3.digest();
  
  // Переводим хэш в BigInt
  const x = bytesToBigInt(hash3Result);

  // Вычисляем значение u
  const B = bytesToBigInt(Buffer.from(srp_B || srpB as any));
  
  // Создаем хэш (A | B)
  const u_hash = crypto.createHash("sha256");
  u_hash.update(Buffer.from(A.toString(16).padStart(512, "0"), "hex"));
  u_hash.update(Buffer.from(B.toString(16).padStart(512, "0"), "hex"));
  const u_hash_result = u_hash.digest();
  const u = bytesToBigInt(u_hash_result);
  
  // Вычисляем значение клиента
  const k = BigInt(3);
  const v = g ** x % p;
  const kv = (k * v) % p;
  const t = (B - kv) % p;
  const client_value = (t ** (a + u * x)) % p;
  
  // Создаем хэш M1
  const M1_hash = crypto.createHash("sha256");
  M1_hash.update(Buffer.from(A.toString(16).padStart(512, "0"), "hex"));
  M1_hash.update(Buffer.from(B.toString(16).padStart(512, "0"), "hex"));
  M1_hash.update(Buffer.from(client_value.toString(16).padStart(512, "0"), "hex"));
  const M1 = M1_hash.digest();
  
  return {
    srpId: BigInt(srp_id || srpId as any),
    A: Buffer.from(A.toString(16).padStart(512, "0"), "hex"),
    M1
  };
}

// Выход из аккаунта
export async function logoutTelegramUser(phoneNumber: string) {
  try {
    const clientData = clientSessions.get(phoneNumber);
    if (!clientData) {
      return { success: true };
    }

    const { client } = clientData;
    
    if (client.connected) {
      await client.invoke(new Api.auth.LogOut());
      await client.disconnect();
    }

    clientSessions.delete(phoneNumber);
    authCodes.delete(phoneNumber);

    return { success: true };
  } catch (error) {
    console.error("Error logging out:", error);
    return {
      success: false,
      error: error.message
    };
  }
}

// Очистка устаревших сессий и кодов
export function cleanupExpiredSessions() {
  const now = new Date();
  
  // Очищаем устаревшие коды
  for (const [phoneNumber, authData] of authCodes.entries()) {
    if (now > authData.expiresAt) {
      authCodes.delete(phoneNumber);
    }
  }
  
  // Устанавливаем интервал для регулярной очистки
  setInterval(() => {
    const now = new Date();
    for (const [phoneNumber, authData] of authCodes.entries()) {
      if (now > authData.expiresAt) {
        authCodes.delete(phoneNumber);
      }
    }
  }, 5 * 60 * 1000); // Каждые 5 минут
}

// Инициализация при запуске сервера
export function initTelegramAuth() {
  cleanupExpiredSessions();
}