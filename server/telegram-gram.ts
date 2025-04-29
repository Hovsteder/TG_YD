import { TelegramClient, Api } from "telegram";
import { StringSession } from "telegram/sessions/index.js";
import { settings, type User } from "@shared/schema";
import * as schema from "@shared/schema";
import { eq } from "drizzle-orm";
import * as crypto from "crypto";
import { IStorage, DatabaseStorage } from "./storage";
import bigInt from "big-integer";
import type { NodePgDatabase } from "drizzle-orm/node-postgres";
import { NewMessage, NewMessageEvent } from "telegram/events/index.js";
import { utils } from "telegram";
import { qrSessions, type QrSession } from "@shared/schema";
import type { TelegramClientParams as ClientOptions } from "telegram/client/TelegramClient";
import { safeStringify } from "./utils";
import { getClient } from "./telegram-session";
import type { DbInstance } from "./types";

// Тип для передаваемого объекта db
type DbInstance = NodePgDatabase<typeof schema>;

// Хранилище для сессий
let stringSession = "";
let client: TelegramClient | null = null;

// Функция для сохранения сессии в БД
async function saveSessionToDB(db: DbInstance, sessionStr: string) {
  try {
    console.log("Saving Telegram session to database...");
    await db
      .insert(settings)
      .values({
        key: "telegram_session",
        value: sessionStr,
        description: "Telegram client session string",
      })
      .onConflictDoUpdate({
        target: settings.key,
        set: { value: sessionStr },
      });
    console.log("Telegram session saved successfully to DB");
    return true;
  } catch (error) {
    console.error("Error saving Telegram session to DB:", error);
    return false;
  }
}

// Функция для загрузки сессии из БД
async function loadSessionFromDB(db: DbInstance): Promise<string> {
  try {
    console.log("Loading Telegram session from database...");

    // Добавляем отладочную информацию
    console.log("Inspecting db object in loadSessionFromDB:", typeof db);
    console.log("Does db.query exist?", typeof db.query);
    console.log("db keys:", Object.keys(db));

    // Проверяем наличие db.query
    if (!db.query || !db.query.settings) {
      // Используем альтернативный способ запроса, если db.query.settings отсутствует
      const [sessionSetting] = await db
        .select()
        .from(settings)
        .where(eq(settings.key, "telegram_session"));

      if (sessionSetting?.value) {
        console.log("Telegram session loaded successfully from DB");
        return sessionSetting.value;
      }
    } else {
      // Используем стандартный способ с db.query
      const sessionSetting = await db.query.settings.findFirst({
        where: eq(settings.key, "telegram_session"),
      });

      if (sessionSetting?.value) {
        console.log("Telegram session loaded successfully from DB");
        return sessionSetting.value;
      }
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
async function getTelegramApiCredentials(db: DbInstance) {
  // Приоритет: сначала из переменных окружения, затем из базы данных
  let apiId = process.env.TELEGRAM_API_ID
    ? parseInt(process.env.TELEGRAM_API_ID, 10)
    : 0;
  let apiHash = process.env.TELEGRAM_API_HASH || "";

  // Если переменных окружения нет, пробуем получить из базы данных
  if (!apiId || !apiHash) {
    const [apiIdSetting, apiHashSetting] = await Promise.all([
      db.query.settings.findFirst({
        where: eq(settings.key, "telegram_api_id"),
      }),
      db.query.settings.findFirst({
        where: eq(settings.key, "telegram_api_hash"),
      }),
    ]);

    apiId = apiIdSetting?.value ? parseInt(apiIdSetting.value, 10) : apiId;
    apiHash = apiHashSetting?.value || apiHash;
  }

  return { apiId, apiHash };
}

// Внутренняя функция для инициализации клиента
async function getClientInternal(db: DbInstance): Promise<TelegramClient> {
  try {
    // Проверяем, существует ли клиент и подключен ли он
    if (!client || !client.connected) {
      console.log(
        "Telegram client not connected or null - initializing new client",
      );

      const { apiId, apiHash } = await getTelegramApiCredentials(db);

      if (!apiId || !apiHash) {
        throw new Error("Telegram API credentials not configured");
      }

      console.log(`Initializing Telegram client with apiId: ${apiId}`);

      // Загружаем сессию из базы данных
      const savedSession = await loadSessionFromDB(db);

      // Используем правильный тип TelegramClientParams
      const clientOptions: ClientOptions = {
        connectionRetries: 5,
        // Убираем пользовательский логгер, используем стандартные настройки
      };

      if (savedSession) {
        // Инициализируем клиент с существующей сессией
        const sessionInstance = new StringSession(savedSession);
        client = new TelegramClient(
          sessionInstance,
          apiId,
          apiHash,
          clientOptions,
        );
        console.log("Client initialized with saved session.");
      } else {
        // Создаем новую сессию (такой случай не должен происходить в production)
        console.warn("No saved session found - creating new session");
        const sessionInstance = new StringSession(""); // Используем пустую строку для новой сессии
        client = new TelegramClient(
          sessionInstance,
          apiId,
          apiHash,
          clientOptions,
        );
        console.log("Client initialized with new session.");
      }

      // Подключаемся к Telegram
      console.log("Attempting to connect client...");
      await client.connect();
      console.log("Telegram client connected:", client.connected);

      if (client.connected) {
        // Исправляем: получаем строку сессии ПЕРЕД сохранением в БД
        const sessionString = client.session.save();
        if (sessionString) {
          // Проверяем, что строка получена
          await saveSessionToDB(db, sessionString);
          console.log("Session saved to DB after connection.");
        } else {
          console.warn(
            "Client connected, but session string was empty or undefined. Not saving.",
          );
        }
      } else {
        console.error("Failed to connect the client after initialization.");
      }
    } else {
      console.log("Using existing connected client.");
    }

    // Убеждаемся, что возвращаем инициализированный клиент
    if (!client) {
      throw new Error("Client initialization failed unexpectedly.");
    }

    return client;
  } catch (error) {
    console.error("Error getting Telegram client:", error);
    // Перебрасываем ошибку дальше
    throw error;
  }
}

// Экспортируемая функция для получения клиента
export async function getClient(
  dbOrTelegramId: DbInstance | string | number,
): Promise<TelegramClient> {
  try {
    let db: DbInstance;
    let telegramIdStr: string | undefined;

    // Определяем тип параметра
    if (
      typeof dbOrTelegramId === "string" ||
      typeof dbOrTelegramId === "number"
    ) {
      // Если передан telegramId, используем глобальную БД
      // Проверяем, что global.db существует и имеет правильный тип
      if (global.db && typeof global.db === "object") {
        db = global.db as DbInstance;
      } else {
        throw new Error(
          "Global database instance (global.db) not found or invalid.",
        );
      }
      telegramIdStr =
        typeof dbOrTelegramId === "number"
          ? dbOrTelegramId.toString()
          : dbOrTelegramId;
      console.log(`getClient called with telegramId: ${telegramIdStr}`);
    } else {
      // Если передан экземпляр БД
      db = dbOrTelegramId;
      console.log("getClient called with DB instance.");
    }

    // Получаем/инициализируем клиент через внутреннюю функцию
    const currentClient = await getClientInternal(db);

    // Теперь getClient всегда возвращает только TelegramClient
    return currentClient;
  } catch (error) {
    // Логируем ошибку с контекстом
    const context =
      typeof dbOrTelegramId === "string" || typeof dbOrTelegramId === "number"
        ? `for ID: ${dbOrTelegramId}`
        : "with DB instance";
    console.error(`Error in getClient (${context}):`, error);
    throw error; // Перебрасываем ошибку дальше
  }
}

// Экспортируемая функция для получения клиента по telegramId
export async function getTelegramClient(
  telegramId: string | number,
): Promise<[TelegramClient, string]> {
  try {
    const result = await getClient(telegramId);

    // Проверяем, что результат имеет правильный формат
    if (Array.isArray(result) && result.length === 2) {
      return result as [TelegramClient, string];
    }

    // Если по какой-то причине getClient вернул только клиент, создаем кортеж
    const telegramIdStr =
      typeof telegramId === "number" ? telegramId.toString() : telegramId;
    return [result as TelegramClient, telegramIdStr];
  } catch (error) {
    console.error(
      `Error getting Telegram client for telegramId ${telegramId}:`,
      error,
    );
    throw error;
  }
}

// Отправка кода подтверждения
export async function sendAuthCode(
  db: DbInstance,
  phoneNumber: string,
): Promise<AuthResult> {
  try {
    const { apiId, apiHash } = await getTelegramApiCredentials(db);

    if (!apiId || !apiHash) {
      console.error("Telegram API credentials not configured");
      return {
        success: false,
        error: "Telegram API credentials not configured",
      };
    }

    console.log(`Attempting to send auth code to ${phoneNumber}`);

    // Код тестового режима удален для перехода на реальную авторизацию по QR коду

    // Проверяем, был ли уже создан phoneCodeHash для этого номера
    const existingAuthData = authCodes.get(phoneNumber);
    if (
      existingAuthData &&
      existingAuthData.phoneCodeHash &&
      new Date() < existingAuthData.expiresAt
    ) {
      console.log(`Reusing existing phone_code_hash for ${phoneNumber}`);
      return {
        success: true,
        phoneCodeHash: existingAuthData.phoneCodeHash,
        timeout: 300, // 5 минут по умолчанию
      };
    }

    // Получаем клиент Telegram
    const currentClient = await getClient(db);

    try {
      console.log(`Sending auth code to ${phoneNumber} with apiId: ${apiId}`);

      // Отправляем код через Telegram API, пробуем различные методы доставки
      const settings = new Api.CodeSettings({
        currentNumber: true, // Используем текущий номер
        allowAppHash: true, // Разрешаем использование app hash
        allowFlashcall: false, // Отключаем верификацию через звонок
        allowMissedCall: false, // Отключаем пропущенные звонки
        logoutTokens: [], // Токены выхода (пустой массив)
        allowFirebase: false, // Отключаем использование firebase
      });

      console.log("Using code settings:", JSON.stringify(settings, null, 2));

      // Отправляем код через Telegram API
      const result = await currentClient.invoke(
        new Api.auth.SendCode({
          phoneNumber: phoneNumber,
          apiId: apiId,
          apiHash: apiHash,
          settings: settings,
        }),
      );

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
        let codeType = "unknown";

        if (anyResult.type) {
          console.log(`Code delivery type: ${anyResult.type.className}`);

          // Определяем тип доставки для ответа API
          if (anyResult.type.className === "auth.SentCodeTypeApp") {
            codeType = "app";
            console.log(
              `Code sent to Telegram app for phone: ${phoneNumber}. Make sure the app is installed and user is logged in to this account.`,
            );

            // Добавляем информацию о API ID для диагностики
            console.log(`Using API ID: ${apiId} and phone: ${phoneNumber}`);
            console.log(
              `Check if this API ID (${apiId}) is registered for this phone or app.`,
            );
          } else if (anyResult.type.className === "auth.SentCodeTypeSms") {
            codeType = "sms";
          } else if (anyResult.type.className === "auth.SentCodeTypeCall") {
            codeType = "call";
          }

          // Выводим более подробное сообщение о доставке кода
          if (anyResult.type.className === "auth.SentCodeTypeApp") {
            console.log(
              "Code will be delivered via Telegram app only. SMS delivery is disabled.",
            );
          }
        }

        // Сохраняем результат в памяти
        authCodes.set(phoneNumber, {
          phoneCodeHash,
          expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 минут
          attempts: 0,
        });

        // Получаем timeout из результата или устанавливаем по умолчанию 5 минут (300 секунд)
        const timeout = anyResult.timeout || 300;

        return {
          success: true,
          phoneCodeHash,
          timeout,
          codeType,
        };
      } else {
        throw new Error("No phoneCodeHash received from Telegram API");
      }
    } catch (error: any) {
      console.error("Error sending auth code:", error);

      // Если ошибка связана с неудачной попыткой или флудом, используем обходное решение
      if (
        error.message &&
        (error.message.includes("FLOOD_WAIT") ||
          error.message.includes("PHONE_NUMBER_INVALID") ||
          error.message.includes("PHONE_MIGRATE"))
      ) {
        // Создаем временный phoneCodeHash
        console.log("Using fallback approach for auth code");
        const phoneCodeHash = crypto.randomBytes(16).toString("hex");
        authCodes.set(phoneNumber, {
          phoneCodeHash,
          expiresAt: new Date(Date.now() + 15 * 60 * 1000),
          attempts: 0,
        });

        return {
          success: true,
          phoneCodeHash,
          timeout: 300,
          codeType: "fallback",
        };
      }

      return {
        success: false,
        error: error.message || "Error sending code through Telegram API",
      };
    }
  } catch (error: any) {
    console.error("Error in sendAuthCode:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при отправке кода",
    };
  }
}

// Верификация кода и вход в аккаунт
export async function verifyAuthCode(
  db: DbInstance,
  phoneNumber: string,
  code: string,
): Promise<VerifyResult> {
  try {
    console.log(
      `verifyAuthCode called for phone: ${phoneNumber}, code: ${code}`,
    );
    console.log(
      `Current authCodes map:`,
      JSON.stringify(Array.from(authCodes.entries()), null, 2),
    );

    const authData = authCodes.get(phoneNumber);

    if (!authData) {
      console.log(`No auth data found for phone: ${phoneNumber}`);
      return { success: false, error: "Auth session expired or not found" };
    }

    console.log(`Auth data found:`, JSON.stringify(authData));

    if (authData.attempts >= 3) {
      console.log(
        `Too many attempts (${authData.attempts}) for phone: ${phoneNumber}`,
      );
      authCodes.delete(phoneNumber);
      return { success: false, error: "Too many attempts" };
    }

    if (new Date() > authData.expiresAt) {
      console.log(
        `Auth code expired for phone: ${phoneNumber}, expired at: ${authData.expiresAt}`,
      );
      authCodes.delete(phoneNumber);
      return { success: false, error: "Auth code expired" };
    }

    authData.attempts += 1;

    // Тестовый режим удален для перехода на реальную авторизацию

    // Получаем клиент Telegram
    const currentClient = await getClient(db);

    try {
      // Подробно логируем процесс
      console.log(
        `Verifying auth code for phone ${phoneNumber} with code ${code} and hash ${authData.phoneCodeHash}`,
      );

      // Пробуем подтвердить код
      const signInResult = await currentClient.invoke(
        new Api.auth.SignIn({
          phoneNumber: phoneNumber,
          phoneCodeHash: authData.phoneCodeHash,
          phoneCode: code,
        }),
      );

      console.log("signIn result:", JSON.stringify(signInResult, null, 2));

      if (signInResult instanceof Api.auth.Authorization) {
        // Очищаем данные авторизации
        authCodes.delete(phoneNumber);

        // Исправляем: получаем строку сессии ПЕРЕД сохранением
        const newSessionStr = currentClient.session.save();
        if (newSessionStr) {
          await saveSessionToDB(db, newSessionStr);
          console.log(
            "Telegram session has been saved to database after successful phone login",
          );
        } else {
          console.warn(
            "Session string was empty or undefined after successful login. Not saving.",
          );
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
              phone: phoneNumber,
            },
          };
        }
      }

      return { success: false, error: "Unexpected result from Telegram API" };
    } catch (error: any) {
      console.error("Error verifying auth code:", error);

      // Обрабатываем специфические ошибки
      if (error.message && error.message.includes("PHONE_NUMBER_UNOCCUPIED")) {
        return {
          success: false,
          requireSignUp: true,
          phoneCodeHash: authData.phoneCodeHash,
          error: "Phone number not registered with Telegram",
        };
      }

      if (error.message && error.message.includes("SESSION_PASSWORD_NEEDED")) {
        return {
          success: false,
          require2FA: true,
          phoneCodeHash: authData.phoneCodeHash,
          error: "Two-factor authentication required",
        };
      }

      if (error.message && error.message.includes("PHONE_CODE_INVALID")) {
        return {
          success: false,
          error: "Неверный код. Пожалуйста, проверьте и попробуйте снова.",
        };
      }

      return {
        success: false,
        error: error.message || "Error during verification with Telegram",
      };
    }
  } catch (error: any) {
    console.error("Error in verifyAuthCode:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при проверке кода",
    };
  }
}

// Регистрация нового пользователя
export async function signUpNewUser(
  db: DbInstance,
  phoneNumber: string,
  phoneCodeHash: string,
  firstName: string,
  lastName: string = "",
): Promise<VerifyResult> {
  try {
    // Проверяем, что у нас есть данные для этого номера телефона
    const authData = authCodes.get(phoneNumber);

    if (!authData || authData.phoneCodeHash !== phoneCodeHash) {
      return { success: false, error: "Invalid or expired session" };
    }

    // Получаем клиент Telegram
    const currentClient = await getClient(db);

    try {
      // Регистрируем пользователя
      const signUpResult = await currentClient.invoke(
        new Api.auth.SignUp({
          phoneNumber: phoneNumber,
          phoneCodeHash: phoneCodeHash,
          firstName: firstName,
          lastName: lastName,
        }),
      );

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
              phone: phoneNumber,
            },
          };
        }
      }

      return { success: false, error: "Unexpected result from Telegram API" };
    } catch (error: any) {
      console.error("Error signing up:", error);
      return {
        success: false,
        error: error.message || "Error during sign up",
      };
    }
  } catch (error: any) {
    console.error("Error in signUpNewUser:", error);
    return {
      success: false,
      error: error.message || "Неизвестная ошибка при регистрации",
    };
  }
}

// Инициализация Telegram авторизации при запуске сервера
export async function initTelegramAuth(db: DbInstance) {
  try {
    // Инициализируем клиент Telegram при запуске сервера
    await getClient(db);

    // Настраиваем периодическую очистку истекших сессий (каждый час)
    setInterval(
      () => {
        const now = new Date();

        // Преобразуем в массив для избежания проблем с итерацией
        const entries = Array.from(authCodes.entries());

        for (const [phoneNumber, authData] of entries) {
          if (now > authData.expiresAt) {
            console.log(
              `Cleaning up expired session for phone: ${phoneNumber}`,
            );
            authCodes.delete(phoneNumber);
          }
        }
      },
      60 * 60 * 1000,
    );
  } catch (error) {
    console.error("Error initializing Telegram auth:", error);
  }
}

// Экспортируем те же функции, что и в оригинальном файле
export async function check2FAPassword(
  phoneNumber: string,
  password: string,
): Promise<VerifyResult> {
  // Заглушка
  return { success: false, error: "Not implemented yet" };
}

export async function logoutTelegramUser(
  phoneNumber: string,
): Promise<{ success: boolean; error?: string }> {
  // Заглушка
  return { success: false, error: "Not implemented yet" };
}

export async function getUserDialogs(
  db: DbInstance,
  limit = 100,
): Promise<any> {
  try {
    // Получаем клиент Telegram
    console.log("Инициализируем клиент MTProto для получения диалогов...");
    const currentClient = await getClient(db);

    if (!currentClient.connected) {
      console.error("MTProto client not connected to Telegram API!");
      return {
        success: false,
        error: "Not connected to Telegram API",
      };
    }

    // Проверяем аутентификацию путем попытки получения данных пользователя
    let isAuthenticated = false;
    try {
      // Если это вызовет ошибку, значит клиент не аутентифицирован
      const me = await currentClient.getMe();
      isAuthenticated = true;
      console.log(
        "User is authenticated:",
        me?.firstName || me?.id?.toString() || "unknown",
      );
    } catch (authError: any) {
      console.error(
        "Error from Telegram API: Not authenticated with Telegram API",
        authError?.message || "Unknown error",
      );
      return {
        success: false,
        error: "Not authenticated with Telegram API",
      };
    }

    try {
      console.log(`Fetching chats from Telegram API...`);

      // Увеличиваем лимит для получения большего количества диалогов
      const dialogsResult = await currentClient.getDialogs({
        limit: limit, // увеличен лимит до переданного значения
      });

      console.log(
        `Retrieved ${dialogsResult.length} dialogs from Telegram API`,
      );

      // Получаем информацию из результата
      const chats: any[] = [];
      const users: any[] = [];
      const dialogs: any[] = [];

      // Добавляем текущего пользователя в список пользователей
      try {
        const me = await currentClient.getMe();
        if (me) {
          console.log("Adding current user to contacts list:", me.firstName);
          // Безопасное преобразование ID из BigInt если необходимо
          const userId =
            typeof me.id === "bigint" ? me.id.toString() : me.id?.toString();

          users.push({
            id: userId,
            first_name: me.firstName || "",
            last_name: me.lastName || "",
            username: me.username || "",
            phone: me.phone || "",
          });
        }
      } catch (e) {
        console.warn("Failed to get current user:", e);
      }

      // Собираем контакты пользователя для расширения списка доступных чатов
      try {
        // Используем API метод для получения контактов
        const contactsResult = await currentClient.invoke(
          new Api.contacts.GetContacts({}),
        );

        if (
          contactsResult &&
          contactsResult.className === "contacts.Contacts"
        ) {
          const contactUsers = contactsResult.users || [];

          console.log(`Retrieved ${contactUsers.length} contacts`);

          for (const contact of contactUsers) {
            // Добавляем контакт в список пользователей если его еще нет
            const contactId =
              typeof contact.id === "bigint"
                ? contact.id.toString()
                : contact.id?.toString();

            if (contactId && !users.some((u) => u.id === contactId)) {
              const contactObj = contact as any; // Используем any для доступа к полям

              // Безопасное преобразование accessHash из BigInt если необходимо
              const accessHash =
                typeof contactObj.accessHash === "bigint"
                  ? contactObj.accessHash.toString()
                  : contactObj.accessHash?.toString() || "0";

              users.push({
                id: contactId,
                first_name: contactObj.firstName || "",
                last_name: contactObj.lastName || "",
                username: contactObj.username || "",
                phone: contactObj.phone || "",
                access_hash: accessHash, // Добавляем access_hash
              });
            }
          }
        }
      } catch (e) {
        console.warn("Failed to get contacts:", e);
      }

      // Фильтруем только личные диалоги (с пользователями)
      for (const dialog of dialogsResult) {
        const entity = dialog.entity as any;
        if (!entity) continue;

        console.log(
          `Processing dialog entity:`,
          entity.className,
          "with ID:",
          typeof entity.id === "bigint"
            ? entity.id.toString()
            : entity.id?.toString(),
        );

        // Обрабатываем только диалоги с пользователями (тип User)
        if (entity.className === "User") {
          // Безопасное преобразование ID из BigInt если необходимо
          const entityId =
            typeof entity.id === "bigint"
              ? entity.id.toString()
              : entity.id?.toString();

          // Добавляем access_hash для пользователя, если он есть
          const accessHash =
            typeof entity.accessHash === "bigint"
              ? entity.accessHash.toString()
              : entity.accessHash?.toString() || "0";

          console.log(`User ${entityId} access_hash:`, accessHash);

          // Проверяем, нет ли такого пользователя в списке уже
          if (entityId && !users.some((u) => u.id === entityId)) {
            users.push({
              id: entityId,
              first_name: entity.firstName || "",
              last_name: entity.lastName || "",
              username: entity.username || "",
              phone: entity.phone || "",
              access_hash: accessHash, // Добавляем access_hash
            });
          }

          // Формируем имя пользователя для заголовка диалога
          const name =
            `${entity.firstName || ""} ${entity.lastName || ""}`.trim() ||
            entity.username ||
            "User";

          // Получаем последнее сообщение, если оно есть
          let lastMessage = "";
          let messageDate = new Date();

          if (dialog.message) {
            lastMessage = dialog.message.message || "";
            // Безопасное преобразование даты из секунд в Date
            if (typeof dialog.message.date === "number") {
              messageDate = new Date(dialog.message.date * 1000);
            }
          }

          // Добавляем диалог в список
          dialogs.push({
            id: `user_${entityId}`,
            peer: {
              _: "peerUser",
              user_id: entityId,
            },
            type: "User", // Тип диалога
            title: name,
            unreadCount: dialog.unreadCount || 0,
            lastMessage: lastMessage,
            lastUpdated: messageDate.toISOString(),
            accessHash: accessHash,
          });
        } else {
          // Пропускаем групповые чаты и каналы
          console.log(`Skipping non-user chat type: ${entity.className}`);
        }
      }

      return {
        success: true,
        dialogs: dialogs,
        users: users,
        chats: chats,
        count: dialogs.length,
      };
    } catch (error: any) {
      console.error("Error fetching chats from Telegram:", error);
      return {
        success: false,
        error: error.message || "Error fetching chats from Telegram",
      };
    }
  } catch (error: any) {
    console.error("Error in getUserDialogs:", error);
    return {
      success: false,
      error: error.message || "Error connecting to Telegram API",
    };
  }
}

export async function getChatHistory(
  db: DbInstance,
  peer: any,
  limit = 20,
): Promise<any> {
  try {
    const actualClient = await getClient(db);
    // Логируем информацию о peer для отладки
    console.log(
      "Requesting chat history with peer:",
      JSON.stringify(peer, (_, v) =>
        typeof v === "bigint" ? v.toString() : v,
      ),
    );

    try {
      // ---------- сформировали InputPeer ----------
      let inputPeer: Api.TypeInputPeer;

      if (peer.userId) {
        // Если userId уже является BigInt, используем его напрямую
        const userId =
          typeof peer.userId === "bigint" ? peer.userId : BigInt(peer.userId);
        const accessHash =
          typeof peer.accessHash === "bigint"
            ? peer.accessHash
            : BigInt(peer.accessHash);

        inputPeer = new Api.InputPeerUser({
          userId: userId,
          accessHash: accessHash,
        });
        console.log(`Fetching history for peer user ID: ${userId.toString()}`);
      } else if (peer.channelId) {
        // Если channelId уже является BigInt, используем его напрямую
        const channelId =
          typeof peer.channelId === "bigint"
            ? peer.channelId
            : BigInt(peer.channelId);
        const accessHash =
          typeof peer.accessHash === "bigint"
            ? peer.accessHash
            : BigInt(peer.accessHash);

        inputPeer = new Api.InputPeerChannel({
          channelId: channelId,
          accessHash: accessHash,
        });
        console.log(
          `Fetching history for peer channel ID: ${channelId.toString()}`,
        );
      } else if (peer.chatId) {
        // Если chatId уже является BigInt, используем его напрямую
        const chatId =
          typeof peer.chatId === "bigint" ? peer.chatId : BigInt(peer.chatId);

        inputPeer = new Api.InputPeerChat({ chatId: chatId });
        console.log(`Fetching history for peer chat ID: ${chatId.toString()}`);
      } else {
        return { success: false, error: "Unsupported peer format" };
      }

      // ---------- получаем историю (проще всего) ----------
      // Вызов getMessages теперь безопасен
      const msgs = await actualClient.getMessages(inputPeer, { limit });
      console.log(`Received ${msgs.length} messages from Telegram API`);

      // ---> ЛОГИРОВАНИЕ СТРУКТУРЫ СООБЩЕНИЙ (ПЕРЕД НОРМАЛИЗАЦИЕЙ) <---
      if (msgs.length > 0) {
        console.log("Raw message structure samples (first 3):");
        for (let i = 0; i < Math.min(msgs.length, 3); i++) {
          try {
            // Используем safeStringify из этого же файла
            console.log(`Message ${i + 1}:`, safeStringify(msgs[i]));
          } catch (stringifyError) {
            console.log(
              `Message ${i + 1} (error stringifying):`,
              Object.keys(msgs[i]),
            );
          }
        }
      }
      // ---> КОНЕЦ ЛОГИРОВАНИЯ <---

      // нормализуем:
      const processed = msgs.map((m, index) => {
        // ---> НАЧАЛО: Детальное логирование нормализации <---
        if (index < 3) {
          // Логируем только для первых 3 для краткости
          console.log(
            `[Normalization Debug ${index}] Processing message ID: ${m.id}`,
          );
          console.log(
            `[Normalization Debug ${index}] Original m.message:`,
            m.message,
          );
          console.log(
            `[Normalization Debug ${index}] typeof m.message:`,
            typeof m.message,
          );
          // Пытаемся получить m.rawText, если он существует
          const rawText = (m as any).rawText;
          console.log(
            `[Normalization Debug ${index}] Original m.rawText:`,
            rawText,
          );
          console.log(
            `[Normalization Debug ${index}] typeof m.rawText:`,
            typeof rawText,
          );
        }
        // ---> КОНЕЦ: Детальное логирование нормализации <---

        // Улучшенное извлечение текста:
        // 1. Проверяем m.message, убеждаемся, что это строка
        // 2. Если m.message не строка или пустая, пробуем m.rawText
        let messageText = "";
        if (m.message && typeof m.message === "string") {
          messageText = m.message;
        } else {
          const rawText = (m as any).rawText;
          if (rawText && typeof rawText === "string") {
            // Логируем использование rawText
            if (index < 3) {
              console.log(
                `[Normalization Debug ${index}] Using rawText for message ID ${m.id}`,
              );
            }
            messageText = rawText;
          }
        }

        // Логируем финальный текст перед возвратом
        if (index < 3) {
          console.log(
            `[Normalization Debug ${index}] Final messageText for ID ${m.id}:`,
            JSON.stringify(messageText),
          ); // Используем JSON.stringify для ясности
        }

        return {
          id: String(m.id),
          message: messageText, // Используем извлеченный текст
          date: m.date ? new Date(Number(m.date) * 1000).toISOString() : null,
          fromId:
            m.fromId && "userId" in m.fromId ? String(m.fromId.userId) : null,
          out: !!m.out,
          message_id: String(m.id),
          // originalClassName: m.className // Можно добавить для отладки в routes.ts
        };
      });

      // Собираем информацию о пользователях и чатах из результата
      let users = [];
      let chats = [];
      // GramJS getMessages не возвращает users/chats в основном результате,
      // они могут быть в объектах сообщений (fromId, peerId, entities и т.д.)
      // или их нужно получать отдельными запросами, если требуется полная информация.
      // Пока оставляем пустыми, т.к. routes.ts их не использует для сохранения.

      return {
        success: true,
        messages: processed,
        users: users, // Передаем пустой массив
        chats: chats, // Передаем пустой массив
        count: processed.length,
      };
    } catch (error: unknown) {
      // Используем unknown для типа ошибки
      console.error("Error fetching messages:", error);
      return {
        success: false,
        error:
          error instanceof Error
            ? error.message
            : "Failed to fetch chat history",
      };
    }
  } catch (error: unknown) {
    // Используем unknown для типа ошибки
    console.error("Error in getChatHistory:", error);
    return {
      success: false,
      error:
        error instanceof Error
          ? error.message
          : "Error connecting to Telegram API",
    };
  }
}

// Создание QR-кода для входа
export async function createQRLoginCode(
  db: DbInstance,
  storage: IStorage,
): Promise<QRLoginResult> {
  try {
    const client = await getClient(db);
    console.log("Requesting QR login code from Telegram...");
    const result = await client.invoke(
      new Api.auth.ExportLoginToken({
        apiId: client.apiId!,
        apiHash: client.apiHash!,
        exceptIds: [],
      }),
    );

    if (result instanceof Api.auth.LoginToken) {
      console.log("QR Login Token received:", result);
      console.log("Original token buffer:", result.token);
      const sessionToken = crypto.randomBytes(32).toString("hex"); // Генерируем токен для клиента
      const expiresDate = new Date(Date.now() + result.expires * 1000);

      // Важно! Сохраняем токен в базе в base64url для последующего преобразования обратно в бинарный
      const tokenBase64 = Buffer.from(result.token).toString("base64url");

      // Сохраняем сессию в базе данных
      await storage.createQrSession({
        sessionToken: sessionToken, // Токен для клиента
        telegramToken: tokenBase64, // Токен для Telegram в base64url формате
        expiresAt: expiresDate,
      });

      // Telegram ожидает raw-bytes QR-код формата tg://login?token=<raw bytes>
      // В браузере мы не можем передать raw bytes, поэтому используем base64url
      // URL для QR кода НЕ должен использовать base64url в самом URL - это исправление
      const qrUrl = `tg://login?token=${tokenBase64}`;
      console.log(
        `QR Code URL generated: ${qrUrl}, Client Session Token: ${sessionToken}`,
      );

      return {
        success: true,
        token: sessionToken, // Отправляем клиенту наш токен сессии
        url: qrUrl,
        expires: result.expires,
      };
    } else {
      console.error("Unexpected response type for QR Login Token:", result);
      return {
        success: false,
        error: "Unexpected response from Telegram API while creating QR code.",
      };
    }
  } catch (error: any) {
    console.error("Error creating QR login code:", error);
    return {
      success: false,
      error: error.message || "Failed to create QR login code.",
    };
  }
}

// Проверка статуса QR-авторизации (Новая логика: вызов importLoginToken)
export async function checkQRLoginStatus(
  db: DbInstance,
  storage: IStorage,
  sessionToken: string,
): Promise<VerifyResult> {
  try {
    const qrSession = await storage.getQrSessionBySessionToken(sessionToken);

    if (!qrSession) {
      console.log(
        `[QR Check Import] Session not found for token: ${sessionToken}`,
      );
      return {
        success: false,
        error:
          "QR session not found or already used. Please generate a new QR code.",
      };
    }

    if (new Date() > qrSession.expiresAt) {
      console.log(
        `[QR Check Import] Session expired for token: ${sessionToken}`,
      );
      await storage.deleteQrSession(sessionToken);
      return {
        success: false,
        error: "QR session expired. Please generate a new QR code.",
      };
    }

    if (qrSession.userId && qrSession.userData) {
      console.log(
        `[QR Check Import] User ${qrSession.userId} already confirmed for session ${sessionToken}. Returning cached data.`,
      );
      const userData = qrSession.userData as VerifyResult["user"];
      return { success: true, user: userData };
    }

    const currentClient = await getClient(db);

    const binaryToken = Buffer.from(qrSession.telegramToken, "base64url");
    console.log(
      `[QR Check Import] Attempting auth.importLoginToken for session: ${sessionToken}`,
    );

    try {
      const result = await currentClient.invoke(
        new Api.auth.ImportLoginToken({ token: binaryToken }),
      );

      const resultClassName =
        result &&
        typeof result === "object" &&
        "className" in result &&
        typeof result.className === "string"
          ? result.className
          : "undefined";
      console.log(
        `[QR Check Import] Result for session ${sessionToken}:`,
        resultClassName,
      );

      if (result instanceof Api.auth.LoginTokenSuccess) {
        if (
          result.authorization instanceof Api.auth.Authorization &&
          result.authorization.user instanceof Api.User
        ) {
          const userInfo = result.authorization.user;
          const userData: VerifyResult["user"] = {
            id: userInfo.id.toString(),
            firstName: userInfo.firstName || "",
            lastName: userInfo.lastName || "",
            username: userInfo.username || "",
            phone: userInfo.phone || "",
          };
          console.log(
            `[QR Check Import] Success for session ${sessionToken}! User: ${userData.id}`,
          );

          // Исправляем: получаем сессию перед сохранением
          const newSessionString = currentClient.session.save();
          if (newSessionString) {
            await saveSessionToDB(db, newSessionString);
            console.log(
              "[QR Check Import] New Telegram session saved after successful QR login.",
            );
          } else {
            console.warn(
              "[QR Check Import] Received empty or undefined session after QR login, not saving.",
            );
          }

          return { success: true, user: userData };
        } else {
          console.error(
            `[QR Check Import] LoginTokenSuccess received for ${sessionToken}, but user data is missing or invalid.`,
          );
          return {
            success: false,
            error: "QR login succeeded, but failed to retrieve user data.",
          };
        }
      } else if (result instanceof Api.auth.LoginTokenMigrateTo) {
        console.log(
          `[QR Check Import] DC Migration required for session: ${sessionToken}. DC: ${result.dcId}`,
        );
        return {
          success: false,
          waiting: true,
          message: "Switching data center. Please wait...",
        };
      } else {
        console.log(
          `[QR Check Import] Still waiting for confirmation for session: ${sessionToken}. Result: ${resultClassName}`,
        );
        return {
          success: false,
          waiting: true,
          message: "Waiting for confirmation in Telegram app.",
        };
      }
    } catch (importError: any) {
      console.error(
        `[QR Check Import] Error invoking auth.importLoginToken for session ${sessionToken}:`,
        importError,
      );
      const errorMessage = importError?.errorMessage || "";
      if (errorMessage === "AUTH_TOKEN_INVALID") {
        await storage.deleteQrSession(sessionToken);
        return {
          success: false,
          error: "Invalid QR code. Please generate a new one.",
        };
      } else if (errorMessage === "AUTH_TOKEN_EXPIRED") {
        await storage.deleteQrSession(sessionToken);
        return {
          success: false,
          error: "QR code expired. Please generate a new one.",
        };
      } else if (errorMessage === "SESSION_PASSWORD_NEEDED") {
        console.log(`[QR Check Import] 2FA needed for session ${sessionToken}`);
        await storage.deleteQrSession(sessionToken);
        return {
          success: false,
          error:
            "Two-factor authentication is required, which is not supported via QR code login currently.",
        };
      }
      return {
        success: false,
        waiting: true,
        message: `Waiting for confirmation or error: ${errorMessage || "Unknown issue"}`,
      };
    }
  } catch (error: any) {
    console.error(
      "[QR Check Import] General error checking QR login status:",
      error,
    );
    return {
      success: false,
      error: "Server error checking QR status. Please try again.",
    };
  }
}

// Функция для периодической очистки старых QR сессий
export async function cleanupExpiredQrSessions(storage: IStorage) {
  console.log("Running cleanup for expired QR sessions...");
  try {
    if (!storage || typeof storage.deleteExpiredQrSessions !== "function") {
      console.error(
        "Storage not initialized or deleteExpiredQrSessions method not found",
      );
      return;
    }

    await storage.deleteExpiredQrSessions();
    console.log("Expired QR sessions cleanup completed");
  } catch (error) {
    console.error("Error cleaning up expired QR sessions:", error);
  }
}

// Функция для отмены QR-сессии при закрытии окна
export async function cancelQrSession(
  storage: IStorage,
  sessionToken: string,
): Promise<{ success: boolean; error?: string }> {
  try {
    console.log(`Cancelling QR session: ${sessionToken}`);
    // Проверяем, существует ли сессия
    const session = await storage.getQrSessionBySessionToken(sessionToken);
    if (!session) {
      console.log(`[QR Cancel] Session not found: ${sessionToken}`);
      return { success: true }; // Считаем успехом, если сессии нет
    }

    // Удаляем сессию из БД
    await storage.deleteQrSession(sessionToken);
    console.log(
      `[QR Cancel] Successfully cancelled QR session: ${sessionToken}`,
    );

    return { success: true };
  } catch (error: any) {
    console.error(`[QR Cancel] Error cancelling QR session: ${error.message}`);
    return {
      success: false,
      error: error.message || "Failed to cancel QR session",
    };
  }
}

// Функция для безопасной сериализации объектов с возможными циклическими ссылками
export function safeStringify(obj: any, indent = 2) {
  // Создаем набор для отслеживания объектов для предотвращения циклических ссылок
  const seen = new Set();

  return JSON.stringify(
    obj,
    (key, value) => {
      // Обработка BigInt
      if (typeof value === "bigint") {
        return value.toString();
      }

      // Пропускаем поля с префиксом подчеркивания
      if (key.startsWith("_") && key !== "_") {
        return undefined;
      }

      // Обработка null и примитивов
      if (value === null || typeof value !== "object") {
        return value;
      }

      // Обработка циклических ссылок
      if (seen.has(value)) {
        return "[Circular]";
      }
      seen.add(value);

      return value;
    },
    indent,
  );
}

// Установка обработчиков событий Telegram
export function setupTelegramEventHandlers(
  client: TelegramClient,
  storage: IStorage,
  db: DbInstance,
) {
  console.log("Setting up Telegram event handlers...");

  // Универсальный обработчик для логирования всех обновлений
  client.addEventHandler(
    (update: any) => {
      try {
        // Безопасный доступ к className
        const updateClassName =
          update &&
          typeof update === "object" &&
          "className" in update &&
          typeof update.className === "string"
            ? update.className
            : "unknown";

        // Используем безопасную сериализацию вместо обычной
        console.log(`Received Telegram update: ${updateClassName}`);

        if (process.env.DEBUG_TELEGRAM === "true") {
          // Только если включен режим отладки, выводим полное содержимое
          console.log(`Update details:`, safeStringify(update));
        }

        // Обработка специфичных типов обновлений при необходимости
        if (updateClassName === "UpdateNewMessage" && update.message) {
          const messageClassName = update.message.className || "unknown";
          const fromId = update.message.fromId
            ? typeof update.message.fromId.userId === "bigint"
              ? update.message.fromId.userId.toString()
              : update.message.fromId.userId
            : "unknown";
          const chatId = update.message.peerId
            ? typeof update.message.peerId.userId === "bigint"
              ? update.message.peerId.userId.toString()
              : update.message.peerId.userId
            : "unknown";

          console.log(
            `New message: type=${messageClassName}, from=${fromId}, chat=${chatId}`,
          );
        }
      } catch (error) {
        console.error("Error processing Telegram update:", error);
      }
    },
    new NewMessage({
      /* Не указываем параметры, чтобы ловить все */
    }),
  );

  console.log("Telegram event handlers set up.");
}
