import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { validateTelegramAuth, generateTwoFACode, verifyTwoFACode } from "./telegram";
import { generateVerificationCode, verifyCode, sendVerificationTelegram } from "./phone-auth";
import { 
  sendAuthCode, 
  verifyAuthCode, 
  signUpNewUser, 
  check2FAPassword, 
  logoutTelegramUser, 
  initTelegramAuth,
  createQRLoginCode,
  checkQRLoginStatus,
  getChatHistory,
  cancelQrSession,
  getUserDialogs
} from "./telegram-gram";
import { z } from "zod";
import { randomBytes, scrypt, timingSafeEqual } from "crypto";
import { promisify } from "util";
import session from "express-session";
import { insertUserSchema, insertSessionSchema, messages, sessions, chats, users } from "@shared/schema";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { db } from "./db";
import { eq, count } from "drizzle-orm";
import connectPgSimple from 'connect-pg-simple'; // Импортируем connect-pg-simple
import { DatabaseStorage, type IStorage } from "./storage"; 
import pg from 'pg'; // Импортируем весь модуль pg
import { readFileSync } from 'fs';
import { join } from 'path';
import * as telegramGram from './telegram-gram';
import { sql } from "drizzle-orm";
import { type Chat } from '@shared/schema'; // Импортируем тип Chat
// Импортируем нужные функции в начале файла
import { getUserDialogs, getChatHistory } from "./telegram-gram"; // Убедимся, что они импортированы
import { type Chat } from '@shared/schema'; // Импортируем тип Chat
// ---> ДОБАВЛЯЕМ ИМПОРТ DbInstance <--- 
import type { NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from "@shared/schema"; // Добавляем импорт schema

// ---> ОПРЕДЕЛЯЕМ ТИП DbInstance <--- 
type DbInstance = NodePgDatabase<typeof schema>;

// Создаем экземпляр основного хранилища данных ЗДЕСЬ, вне registerRoutes
const storage: IStorage = new DatabaseStorage();

// Хелперы для работы с паролями
const scryptAsync = promisify(scrypt);

// Функция для хеширования пароля
async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString("hex");
  const buf = (await scryptAsync(password, salt, 64)) as Buffer;
  return `${buf.toString("hex")}.${salt}`;
}

// Функция для сравнения паролей
async function comparePasswords(supplied: string, stored: string): Promise<boolean> {
  const [hashed, salt] = stored.split(".");
  const hashedBuf = Buffer.from(hashed, "hex");
  const suppliedBuf = (await scryptAsync(supplied, salt, 64)) as Buffer;
  return timingSafeEqual(hashedBuf, suppliedBuf);
}

// Определение схем валидации для API запросов
const telegramAuthSchema = z.object({
  id: z.string(),
  first_name: z.string(),
  username: z.string().optional(),
  photo_url: z.string().optional(),
  auth_date: z.string(),
  hash: z.string()
});

const twoFACodeSchema = z.object({
  code: z.string().length(5) // Код должен быть 5 символов
});

// Схема для запроса кода подтверждения по телефону
const requestPhoneCodeSchema = z.object({
  phoneNumber: z.string().min(10).max(15) // Формат телефона +1234567890
});

// Схема для верификации кода подтверждения по телефону
const verifyPhoneCodeSchema = z.object({
  phoneNumber: z.string().min(10).max(15),
  code: z.string().length(5) // Код должен быть 5 символов
});

// Схема для установки пароля
const setPasswordSchema = z.object({
  phoneNumber: z.string().min(10).max(15),
  password: z.string().min(8).max(100),
  firstName: z.string().optional(),
  lastName: z.string().optional(),
  email: z.string().email().optional()
});

// Схема для логина по телефону/паролю
const phoneLoginSchema = z.object({
  phoneNumber: z.string().min(10).max(15),
  password: z.string().min(1)
});

// Схема для проверки QR-кода авторизации
const qrTokenSchema = z.object({
  token: z.string().min(1)
});

// Создаем экземпляр хранилища сессий
const PGStore = connectPgSimple(session);

// Функция для проверки и создания таблицы сессий
async function setupSessionTable() {
  try {
    console.log("Проверка и создание таблицы session для хранения сессий...");
    
    // Используем соединение из конфигурации приложения
    const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
    
    // Проверяем существование таблицы session
    const checkTableResult = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'session'
      );
    `);
    
    const tableExists = checkTableResult.rows[0].exists;
    
    if (!tableExists) {
      console.log("Таблица session не существует, создаем...");
      
      try {
        // Читаем SQL-скрипт для создания таблицы
        const sqlPath = join(process.cwd(), 'session-table.sql');
        const sqlScript = readFileSync(sqlPath, 'utf8');
        
        // Выполняем SQL-скрипт
        await pool.query(sqlScript);
        console.log("Таблица session успешно создана");
      } catch (readError) {
        console.error("Ошибка при чтении или выполнении SQL-скрипта:", readError);
        console.error("Пожалуйста, выполните скрипт session-table.sql вручную");
      }
    } else {
      // Проверяем наличие колонки sid
      const checkSidColumnResult = await pool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.columns 
          WHERE table_name = 'session' AND column_name = 'sid'
        );
      `);
      
      const sidColumnExists = checkSidColumnResult.rows[0].exists;
      
      if (!sidColumnExists) {
        console.error("Таблица session существует, но не содержит требуемой колонки 'sid'");
        console.error("Пожалуйста, выполните скрипт session-table.sql вручную");
      } else {
        console.log("Таблица session существует и содержит требуемые колонки");
      }
    }
    
    // Закрываем соединение
    await pool.end();
  } catch (error) {
    console.error("Ошибка при настройке таблицы сессий:", error);
  }
}

// Отдельная асинхронная функция для обработки логина по телефону
async function handlePhoneLogin(req: Request, res: Response, next: NextFunction) {
  try {
    const user = req.user as any;
    
    if (!user) {
       // Эта проверка на всякий случай, passport должен был вернуть ошибку раньше
       return res.status(401).json({ message: 'Не авторизован' });
    }
    
    // Создаем лог о входе (теперь storage доступен)
    await storage.createLog({
      userId: user.id,
      action: 'user_login',
      details: { phoneNumber: user.phoneNumber },
      ipAddress: req.ip
    });

    // Генерируем токен сессии для API (если он не был создан ранее)
    const sessionToken = (req.session as any).token || randomBytes(48).toString('hex');
    if (!(req.session as any).token) {
        (req.session as any).token = sessionToken;
        await storage.createSession({
             userId: user.id,
             sessionToken,
             ipAddress: req.ip || null,
             userAgent: req.headers['user-agent'] || null,
             expiresAt: new Date(Date.now() + (30 * 24 * 60 * 60 * 1000)) // 30 дней
        });
    }

    // Отправляем успешный ответ
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        isAdmin: user.isAdmin
      },
      sessionToken // Отправляем токен сессии
    });
  } catch (error) {
    console.error('Phone login handler error:', error);
    next(error); // Передаем ошибку дальше
  }
}

// Обновляем сигнатуру, чтобы принимать storage (хотя он теперь глобальный для этого модуля)
// Оставим аргумент для ясности, но будем использовать storage, объявленный выше
export async function registerRoutes(app: Express, /* storage: IStorage */): Promise<Server> {
  // Проверяем и инициализируем таблицу сессий
  await setupSessionTable();
  
  // Эндпоинт для проверки работоспособности приложения
  app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
  });
  
  // Настройка сессий с connect-pg-simple
  app.use(session({
    store: new PGStore({
      pool: (db as any).$client, // Используем .$client для доступа к pool
      tableName: 'session' // ИСПРАВЛЕНО: Имя таблицы для express-session
    }),
    secret: process.env.SESSION_SECRET || randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 1 неделя
    }
  }));

  // Инициализация Passport
  app.use(passport.initialize());
  app.use(passport.session());

  // Сериализация и десериализация пользователя
  passport.serializeUser((user: any, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id: number, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user);
    } catch (err) {
      done(err);
    }
  });

  // Настройка LocalStrategy для Passport
  passport.use(new LocalStrategy(
    { usernameField: 'phoneNumber' }, // Используем phoneNumber как username
    async (phoneNumber, password, done) => {
      try {
        const user = await storage.getUserByPhoneNumber(phoneNumber);
        if (!user) {
          return done(null, false, { message: 'Пользователь не найден' });
        }
        if (!user.password) {
            return done(null, false, { message: 'Пароль не установлен' });
        }
        const isMatch = await comparePasswords(password, user.password);
        if (!isMatch) {
          // Логгируем неудачную попытку
          await storage.createLog({
            userId: user.id,
            action: 'login_failed',
            details: { phoneNumber, reason: 'invalid_password' },
            ipAddress: undefined // IP недоступен здесь
          });
          return done(null, false, { message: 'Неверный пароль' });
        }
        // Обновляем lastLogin
        await storage.updateUser(user.id, { lastLogin: new Date() });
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  ));

  // Настройка LocalStrategy для входа админа по имени пользователя и паролю
  passport.use('admin-local', new LocalStrategy({
      usernameField: 'username', // поле для имени пользователя в запросе
      passwordField: 'password'  // поле для пароля в запросе
    },
    async (username, password, done) => {
      try {
        // Ищем пользователя по имени пользователя
        const userResult = await db.select().from(users).where(eq(users.username, username)).limit(1);
        const user = userResult[0];

        // Если пользователь не найден или он не админ
        if (!user || !user.isAdmin) {
          return done(null, false, { message: 'Неверное имя пользователя или пароль.' });
        }
        
        // Проверяем пароль
        if (!user.password) {
           // Если хеша нет И это пользователь 'admin' И введен пароль 'admin'
           if (user.username === 'admin' && password === 'admin') {
              console.log(`[Admin Login] First login for 'admin'. Setting password hash.`);
              try {
                const newPasswordHash = await hashPassword(password); // Генерируем хеш
                // Обновляем пользователя в БД
                await db.update(users)
                  .set({ password: newPasswordHash })
                  .where(eq(users.username, user.username));
                console.log(`[Admin Login] Password hash set successfully for 'admin'. Proceeding with login.`);
                // Считаем пароль верным и продолжаем вход
                return done(null, user); 
              } catch (updateError) {
                console.error(`[Admin Login] Failed to set password hash for 'admin':`, updateError);
                return done(updateError); // Возвращаем ошибку обновления
              }
           } else {
              // Если хеша нет, и это не первый вход админа с паролем 'admin'
              return done(null, false, { message: 'Учетная запись администратора не настроена для входа по паролю.' });
           }
        }
        
        // Если хеш существует, сравниваем пароли
        const isMatch = await comparePasswords(password, user.password);

        if (!isMatch) {
          return done(null, false, { message: 'Неверное имя пользователя или пароль.' });
        }

        // Пользователь найден и пароль совпадает
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  ));

  // Middleware для проверки аутентификации
  const isAuthenticated = async (req: Request, res: Response, next: any) => {
    // Проверка стандартной аутентификации
    if (req.isAuthenticated()) {
      return next();
    }
    
    // Проверка авторизации через токен сессии
    const sessionToken = req.headers.authorization?.startsWith('Bearer ') 
      ? req.headers.authorization.substring(7)
      : null;
      
    if (sessionToken) {
      try {
        // Получаем сессию по токену
        const session = await storage.getSession(sessionToken);
        
        if (session && session.expiresAt && new Date() < session.expiresAt) {
          // Получаем пользователя по ID сессии
          const user = await storage.getUser(session.userId);
          
          if (user) {
            // Авторизуем пользователя
            req.login(user, (err) => {
              if (err) {
                console.error("Error logging in user via token:", err);
                return res.status(401).json({ message: 'Не авторизован' });
              }
              // Продолжаем выполнение запроса
              return next();
            });
            return;
          }
        }
      } catch (error) {
        console.error("Session authentication error:", error);
      }
    }
    
    // Если все проверки не прошли, возвращаем ошибку
    res.status(401).json({ message: 'Не авторизован' });
  };

  // Middleware для проверки прав администратора
  const isAdmin = (req: Request, res: Response, next: any) => {
    // Проверка авторизации через заголовок Authorization или Admin-Authorization
    const adminToken = req.headers['admin-authorization'] as string || req.headers['authorization'] as string;
    
    if (adminToken) {
      try {
        // Извлекаем токен из Bearer формата, если такой есть
        const token = adminToken.startsWith('Bearer ') ? adminToken.substring(7) : adminToken;
        
      // Проверяем токен администратора
        storage.getSession(token)
        .then(session => {
            if (session && session.userId) {
            // Получаем данные пользователя по ID из сессии
              return storage.getUserById(session.userId);
          }
          return null;
        })
        .then(user => {
          if (user && user.isAdmin) {
              // Сохраняем информацию о пользователе-администраторе в объекте запроса
              (req as any).admin = {
                id: user.id,
                isAdmin: true
              };
            next();
          } else {
            res.status(403).json({ message: 'Доступ запрещен' });
          }
        })
        .catch(err => {
            console.error('Ошибка при проверке прав администратора:', err);
            res.status(500).json({ message: 'Ошибка сервера' });
          });
      } catch (error) {
        console.error('Ошибка при обработке токена администратора:', error);
        res.status(500).json({ message: 'Ошибка сервера' });
      }
    } else {
    res.status(403).json({ message: 'Доступ запрещен' });
    }
  };

  // API маршруты
  // 1. Telegram авторизация (старый метод, можно оставить или удалить)
  app.post('/api/auth/telegram', async (req, res, next) => {
    try {
      const authData = telegramAuthSchema.parse(req.body);
      
      // Проверка подписи данных от Telegram
      const isValid = await validateTelegramAuth(authData);
      if (!isValid) {
        return res.status(400).json({ message: 'Недействительные данные авторизации' });
      }

      // Поиск пользователя в БД или создание нового
      let user = await storage.getUserByTelegramId(authData.id);
      
      if (!user) {
        // Создаем нового пользователя
        const newUser = {
          telegramId: authData.id,
          firstName: authData.first_name,
          username: authData.username || null,
          avatarUrl: authData.photo_url || null,
          lastLogin: new Date()
        };

        user = await storage.createUser(newUser);
        
        // Создаем лог о регистрации
        await storage.createLog({
          userId: user.id,
          action: 'user_registered',
          details: { telegram_id: authData.id },
          ipAddress: req.ip
        });
        
        // Отправляем уведомление администратору о новом пользователе
        try {
          const adminChatId = await storage.getSettingValue("admin_chat_id");
          const notificationsEnabled = await storage.getSettingValue("notifications_enabled");
          
          if (notificationsEnabled === "true" && adminChatId && user.telegramId) {
            const { sendNewUserNotification } = await import('./telegram');
            await sendNewUserNotification(adminChatId, {
              id: user.id,
              telegramId: user.telegramId,
              username: user.username || undefined,
              firstName: user.firstName || undefined,
              lastName: user.lastName || undefined
            });
          } else if (notificationsEnabled === "true" && adminChatId) {
            // Если у пользователя нет telegramId, но нужно отправить уведомление
            const { getBotInstance } = await import('./telegram');
            const botInstance = await getBotInstance();
            const message = `🔔 *Новый пользователь зарегистрировался*\n\n`
              + `👤 Имя: ${user.firstName || 'Неизвестно'} ${user.lastName || ''}\n`
              + `📱 Телефон: ${user.phoneNumber || 'Не указан'}\n`
              + `✉️ Email: ${user.email || 'Не указан'}\n\n`
              + `Всего пользователей: ${await storage.countUsers()}`;
            
            await botInstance.api.sendMessage(adminChatId, message, { parse_mode: "Markdown" });
          }
        } catch (notificationError) {
          console.error("Failed to send admin notification:", notificationError);
          // Не выбрасываем ошибку, чтобы не прерывать процесс регистрации
        }
      } else {
        // Обновляем данные существующего пользователя
        user = await storage.updateUser(user.id, {
          firstName: authData.first_name,
          username: authData.username || user.username,
          avatarUrl: authData.photo_url || user.avatarUrl,
          lastLogin: new Date()
        }) || user;
        
        // Создаем лог о входе
        await storage.createLog({
          userId: user.id,
          action: 'user_login',
          details: { telegram_id: authData.id },
          ipAddress: req.ip
        });
      }

      // Генерируем 2FA код и отправляем пользователю
      await generateTwoFACode(authData.id);

      res.json({
        success: true,
        telegramId: authData.id,
        requireTwoFA: true
      });
    } catch (error) {
      console.error('Auth error:', error);
      res.status(500).json({ message: 'Ошибка аутентификации' });
    }
  });

  // 2. Двухфакторная аутентификация Telegram
  app.post('/api/auth/2fa', isAuthenticated, async (req, res) => {
    try {
      const { telegramId, code } = req.body;
      
      if (!telegramId || !code) {
        return res.status(400).json({ message: 'Отсутствуют обязательные параметры' });
      }

      // Проверка кода
      const isValid = verifyTwoFACode(telegramId, code);
      
      if (!isValid) {
        return res.status(400).json({ message: 'Неверный код или истек срок действия' });
      }

      // Получаем пользователя
      const user = await storage.getUserByTelegramId(telegramId);
      
      if (!user) {
        return res.status(404).json({ message: 'Пользователь не найден' });
      }

      // Создаем сессию
      const sessionToken = randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 1 неделя
      
      await storage.createSession({
        userId: user.id,
        sessionToken,
        ipAddress: req.ip || null,
        userAgent: req.headers['user-agent'] || null,
        expiresAt
      });

      // Авторизуем пользователя
      req.login(user, (err) => {
        if (err) {
          return res.status(500).json({ message: 'Ошибка авторизации' });
        }
        
        // Создаем лог о 2FA
        storage.createLog({
          userId: user.id,
          action: '2fa_verified',
          details: { telegram_id: telegramId },
          ipAddress: req.ip
        });

        res.json({
          success: true,
          user: {
            id: user.id,
            telegramId: user.telegramId,
            username: user.username,
            firstName: user.firstName,
            lastName: user.lastName,
            avatarUrl: user.avatarUrl,
            isAdmin: user.isAdmin
          },
          sessionToken
        });
      });
    } catch (error) {
      console.error('2FA verification error:', error);
      res.status(500).json({ message: 'Ошибка проверки кода' });
    }
  });

  // 3. Запрос кода подтверждения по телефону
  app.post('/api/auth/phone/request-code', async (req, res, next) => {
    try {
      const { phoneNumber } = requestPhoneCodeSchema.parse(req.body);
      
      // Отправляем запрос на получение кода через Telegram API
      const result = await sendAuthCode(db, phoneNumber);
      
      if (!result.success) {
        return res.status(500).json({ 
          success: false,
          message: result.error || 'Не удалось отправить код' 
        });
      }
      
      // Создаем лог о запросе кода
      await storage.createLog({
        userId: null,
        action: 'phone_code_requested',
        details: { phoneNumber },
        ipAddress: req.ip
      });
      
      const responseMsg = {
        success: true,
        message: 'Код подтверждения отправлен через приложение Telegram',
        phoneCodeHash: result.phoneCodeHash,
        expiresIn: result.timeout || 600, // по умолчанию 10 минут
        codeDeliveryType: 'app' // Только через приложение, SMS отключен
      };
      
      // Добавляем информацию о способе доставки кода, если она доступна
      if (result.codeType) {
        responseMsg.codeDeliveryType = result.codeType;
      }
      
      res.json(responseMsg);
    } catch (error) {
      console.error('Phone code request error:', error);
      res.status(500).json({ 
        success: false,
        message: error instanceof Error ? error.message : 'Ошибка отправки кода' 
      });
    }
  });
  
  // 4. Верификация кода подтверждения по телефону
  app.post('/api/auth/phone/verify-code', async (req, res, next) => {
    try {
      const { phoneNumber, code } = verifyPhoneCodeSchema.parse(req.body);
      
      // Проверка кода через Telegram API
      const verifyResult = await verifyAuthCode(db, phoneNumber, code);
      
      // Обработка ошибок верификации
      if (!verifyResult.success) {
        // Обработка requireSignUp и require2FA (оставляем, если нужно)
        if (verifyResult.requireSignUp) {
        return res.status(400).json({ 
          success: false, 
          requireSignUp: true,
                phoneCodeHash: verifyResult.phoneCodeHash,
                message: verifyResult.error || 'Номер не зарегистрирован в Telegram' 
        });
      }
      if (verifyResult.require2FA) {
            return res.status(400).json({ 
                success: false, 
          require2FA: true,
                phoneCodeHash: verifyResult.phoneCodeHash,
                message: verifyResult.error || 'Требуется двухфакторная аутентификация' 
            });
        }
        // Общая ошибка верификации
        return res.status(400).json({ 
          success: false, 
          message: verifyResult.error || 'Неверный код или истек срок действия' 
        });
      }
      
      // ---> НАЧАЛО ИЗМЕНЕНИЙ <--- 
      
      // Успешная верификация! Получаем данные пользователя из Telegram
      const telegramUser = verifyResult.user;
      if (!telegramUser || !telegramUser.id) {
        console.error("Verification successful, but Telegram user data missing:", verifyResult);
        return res.status(500).json({ 
          success: false,
          message: 'Не удалось получить данные пользователя после верификации' 
        });
      }
      
      const telegramId = telegramUser.id; // Получаем Telegram ID

      // Проверяем, существует ли пользователь с таким телефоном в нашей БД
      let user = await storage.getUserByPhoneNumber(phoneNumber);
      let isNewUserInApp = false;
      
      if (user) {
        // Пользователь существует, обновляем его данные
        console.log(`User ${user.id} (phone: ${phoneNumber}) verified. Updating data.`);
        user = await storage.updateUser(user.id, {
          isVerified: true,
          verificationCode: null, // Очищаем код верификации
          verificationCodeExpires: null,
          telegramId: telegramId, // <--- Сохраняем/обновляем Telegram ID
          firstName: telegramUser.firstName || user.firstName, // Обновляем имя, если есть
          lastName: telegramUser.lastName || user.lastName,   // Обновляем фамилию, если есть
          username: telegramUser.username || user.username,     // Обновляем юзернейм, если есть
          lastLogin: new Date()
        }) || user; // Берем обновленного пользователя

        await storage.createLog({ userId: user.id, action: 'user_login_phone_code', details: { phoneNumber }, ipAddress: req.ip });

      } else {
        // Пользователя нет, создаем нового на основе данных от Telegram
        console.log(`User with phone ${phoneNumber} not found. Creating new user.`);
        isNewUserInApp = true;
        user = await storage.createUser({
          phoneNumber,
          telegramId: telegramId, // <--- Сохраняем Telegram ID
          firstName: telegramUser.firstName || null,
          lastName: telegramUser.lastName || null,
          username: telegramUser.username || null,
          isVerified: true,
          verificationCode: null,
          verificationCodeExpires: null,
          lastLogin: new Date(),
          // Пароль НЕ устанавливаем здесь
        });

        await storage.createLog({ userId: user.id, action: 'user_registered_phone_code', details: { phoneNumber, telegramId }, ipAddress: req.ip });
        
        // Отправляем уведомление администратору (если нужно)
        // ... (код уведомления можно добавить сюда) ...
      }

      // --- Убрали проверку `if (!user.password)` и возврат `requirePassword: true` ---

      // Создаем сессию для пользователя (существующего или нового)
        const sessionToken = randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 1 неделя
        
        await storage.createSession({
          userId: user.id,
          sessionToken,
          ipAddress: req.ip || null,
          userAgent: req.headers['user-agent'] || null,
          expiresAt
        });
        
      // Авторизуем пользователя в сессии Express
        req.login(user, (err) => {
          if (err) {
          console.error("Error logging in user after phone code verification:", err);
            return res.status(500).json({ 
              success: false,
            message: 'Ошибка автоматической авторизации после верификации' 
            });
          }
          
        // Возвращаем успешный ответ с данными пользователя и токеном
        console.log(`User ${user.id} successfully logged in via phone code. Returning session token.`);
        res.json({
            success: true,
          user: { // Отправляем безопасные данные
              id: user?.id,
              phoneNumber: user?.phoneNumber,
              username: user?.username,
              firstName: user?.firstName,
              lastName: user?.lastName,
              isAdmin: user?.isAdmin
            },
          sessionToken,
          isNewUser: isNewUserInApp // Можно передать флаг, если фронтенду это нужно
        }); // <-- Отправляем ответ КЛИЕНТУ СРАЗУ

        // ---> ЗАПУСК ФОНОВОЙ СИНХРОНИЗАЦИИ ПОСЛЕ ОТПРАВКИ ОТВЕТА <--- 
        console.log(`Initiating background sync for user ${user.id}...`);
        initiateBackgroundSync(user.id, db, storage).catch(syncError => {
            // Логируем ошибку фоновой синхронизации, но не влияем на пользователя
            console.error(`[Background Sync] Uncaught error for user ${user.id}:`, syncError);
        });
        // Мы НЕ ждем (await) завершения initiateBackgroundSync

      }); // Конец req.login callback

      // ---> КОНЕЦ ИЗМЕНЕНИЙ <--- 

    } catch (error) {
      console.error('Phone code verification error:', error);
      // Проверяем, является ли ошибка ZodError для более информативного ответа
      if (error instanceof z.ZodError) {
          return res.status(400).json({ 
            success: false, 
            message: 'Неверный формат данных', 
            errors: error.errors 
          });
      }
      res.status(500).json({ 
        success: false,
        message: error instanceof Error ? error.message : 'Ошибка проверки кода' 
      });
    }
  });
  
  // 5. Установка пароля (после верификации телефона)
  app.post('/api/auth/phone/set-password', async (req, res, next) => {
    try {
      const { phoneNumber, password, firstName, lastName, email } = setPasswordSchema.parse(req.body);
      
      // Проверяем существование пользователя
      let user = await storage.getUserByPhoneNumber(phoneNumber);
      
      if (!user) {
        return res.status(404).json({ message: 'Пользователь не найден' });
      }
      
      // Хешируем пароль
      const hashedPassword = await hashPassword(password);
      
      // Обновляем данные пользователя
      user = await storage.updateUser(user.id, {
        password: hashedPassword,
        firstName: firstName || user.firstName,
        lastName: lastName || user.lastName,
        email: email || user.email,
        lastLogin: new Date()
      }) || user;
      
      // Создаем сессию
      const sessionToken = randomBytes(32).toString('hex');
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 1 неделя
      
      await storage.createSession({
        userId: user.id,
        sessionToken,
        ipAddress: req.ip || null,
        userAgent: req.headers['user-agent'] || null,
        expiresAt
      });
      
      // Логируем пользователя
      req.login(user, (err) => {
        if (err) {
          return res.status(500).json({ message: 'Ошибка авторизации' });
        }
        
        // Создаем лог об установке пароля
        storage.createLog({
          userId: user.id,
          action: 'password_set',
          details: { phoneNumber },
          ipAddress: req.ip
        });
        
        res.json({
          success: true,
          user: {
            id: user.id,
            phoneNumber: user.phoneNumber,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            isAdmin: user.isAdmin
          },
          sessionToken
        });
      });
    } catch (error) {
      console.error('Set password error:', error);
      res.status(500).json({ message: 'Ошибка установки пароля' });
    }
  });
  
  // 6. Логин по телефону и паролю
  app.post('/api/auth/phone/login', passport.authenticate('local'), handlePhoneLogin);

  // 7. Выход из системы
  app.post('/api/auth/logout', async (req, res, next) => {
    try {
      const user = req.user as any;
      
      // Создаем лог о выходе
      await storage.createLog({
        userId: user.id,
        action: 'user_logout',
        details: { },
        ipAddress: req.ip
      });
      
      // Удаляем сессию, если передан токен
      const { sessionToken } = req.body;
      if (sessionToken) {
        await storage.deleteSession(sessionToken);
      }
      
      req.logout((err) => {
        if (err) {
          return res.status(500).json({ message: 'Ошибка выхода из системы' });
        }
        
        req.session.destroy((err) => {
          if (err) {
            console.error('Session destruction error:', err);
          }
          res.json({ success: true });
        });
      });
    } catch (error) {
      console.error('Logout error:', error);
      res.status(500).json({ message: 'Ошибка выхода из системы' });
    }
  });

  // 8. Получение данных текущего пользователя
  app.get('/api/auth/me', isAuthenticated, (req, res) => {
    const user = req.user as any;
    
    res.json({
      id: user.id,
      telegramId: user.telegramId,
      phoneNumber: user.phoneNumber,
      email: user.email,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      avatarUrl: user.avatarUrl,
      isAdmin: user.isAdmin,
      isVerified: user.isVerified
    });
  });

  // 9. QR-код авторизация: Создание
  app.get('/api/auth/qr/create', async (req, res, next) => {
    try {
      // Передаем storage в createQRLoginCode
      const result = await createQRLoginCode(db, storage);
      if (result.success) {
        res.status(200).json(result);
      } else {
        res.status(500).json(result);
      }
    } catch (error) {
      next(error);
    }
  });

  // 10. QR-код авторизация: Проверка статуса и вход
  app.post('/api/auth/qr/check', async (req: Request, res: Response) => {
    try {
      const { token } = qrTokenSchema.parse(req.body);
      console.log(`[QR Check Route] Checking status for session: ${token}`);
      // Передаем db и storage в функцию проверки
      const result = await checkQRLoginStatus(db, storage, token);
      console.log(`[QR Check Route] Result for session ${token}:`, result);
      
      if (result.success && result.user) {
        // Успешный вход - устанавливаем сессию пользователя
        // (В этой точке пользователь уже аутентифицирован через Telegram)
        // Найдем или создадим пользователя в нашей БД
        let appUser = await storage.getUserByTelegramId(result.user.id);
        if (!appUser) {
             appUser = await storage.createUser({
                 telegramId: result.user.id,
                 username: result.user.username || `tg_${result.user.id}`,
                 firstName: result.user.firstName,
                 lastName: result.user.lastName,
                 // Дополнительные поля можно установить по умолчанию или оставить null
             });
        }

        // Устанавливаем сессию для пользователя в нашем приложении
        req.login(appUser, async (err) => {
           if (err) {
               console.error(`[QR Check Route] Error setting user session for ${token}:`, err);
               return res.status(500).json({ success: false, error: "Failed to set user session after QR login." });
           }
           console.log(`[QR Check Route] Session set successfully for user ${appUser.id} via QR token ${token}`);
           
           // Удаляем использованную QR-сессию из базы данных
           try {
               await storage.deleteQrSession(token);
               console.log(`[QR Check Route] Deleted used QR session: ${token}`);
           } catch (deleteError) {
                // Логируем ошибку, но не прерываем пользователя
                console.error(`[QR Check Route] Failed to delete QR session ${token}:`, deleteError); 
           }
           
           // Отправляем клиенту данные пользователя
           res.json({ 
                success: true, 
                user: { // Отправляем только безопасные данные
                    id: appUser.id,
                    username: appUser.username,
                    firstName: appUser.firstName,
                    lastName: appUser.lastName,
                    isAdmin: appUser.isAdmin
                }
            }); 
        });

      } else if (result.waiting) {
        // Ожидаем подтверждения
        console.log(`[QR Check Route] Waiting for confirmation for session: ${token}`);
        res.json({ success: false, waiting: true, message: result.message });
      } else {
        // Ошибка проверки (токен истек, невалиден и т.д.)
        console.log(`[QR Check Route] Check failed for session ${token}: ${result.error}`);
        res.status(400).json({ success: false, error: result.error || "Failed to verify QR code." });
      }
    } catch (error: any) {
      console.error('[QR Check Route] Error:', error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ success: false, error: "Invalid token format." });
      }
      res.status(500).json({ success: false, error: "Internal server error checking QR status." });
    }
  });

  // 11. QR-код авторизация: Отмена сессии
  app.post('/api/auth/qr/cancel', async (req, res, next) => {
    // !! Нужно исправить получение токена !!
    // Фронтенд передает { token: "..." }
    const { token: sessionToken } = z.object({ token: z.string() }).parse(req.body);
    try {
      // Передаем storage в cancelQrSession
      const result = await cancelQrSession(storage, sessionToken);
      res.status(result.success ? 200 : 500).json(result);
    } catch (error) {
      next(error);
    }
  });

  // 2. Получение списка чатов пользователя
  app.get('/api/chats', async (req, res) => {
    try {
      // Проверяем авторизацию пользователя
      if (!req.user) {
        console.warn('GET /api/chats - User not authenticated');
        return res.status(401).json({ success: false, error: 'User not authenticated' });
      }
      
      const userId = (req.user as any).id;
      
      // Получаем telegramId пользователя из БД
      const user = await storage.getUser(userId);
      if (!user || !user.telegramId) {
        console.warn('GET /api/chats - User not authenticated with Telegram');
        return res.status(401).json({ success: false, error: 'User not authenticated with Telegram' });
      }
      
      console.log(`GET /api/chats - UserID: ${userId}, TelegramID: ${user.telegramId}`);
      
      // Сначала получаем список чатов из нашей БД
      console.log(`GET /api/chats - Получаем существующие чаты из БД...`);
      const existingChats = await storage.getUserChats(userId);
      console.log(`GET /api/chats - Найдено ${existingChats.length} чатов в БД`);
      
      // Всегда запрашиваем обновленные чаты из Telegram (не только если их меньше 5)
      console.log(`GET /api/chats - Обновляем чаты из Telegram...`);
      const tgDialogs = await getUserDialogs(db, 200); // Увеличенный лимит для получения максимального количества личных чатов
      
      if (tgDialogs.success && tgDialogs.dialogs) {
        console.log(`GET /api/chats - Получено ${tgDialogs.dialogs.length} диалогов из Telegram`);
        console.log(`GET /api/chats - Обрабатываем диалоги...`);
        
        // Обработка полученных диалогов
        for (const dialog of tgDialogs.dialogs) {
          // Проверяем, что это личный чат (с пользователем)
          if (dialog.type === 'User') {
            // Получаем информацию о пользователе
            const userInfo = tgDialogs.users.find((u: any) => u.id === dialog.peer.user_id.toString());
            if (!userInfo) {
              console.warn(`GET /api/chats - Не найдена информация о пользователе для диалога ${dialog.id}`);
              continue;
            }
            
            // Формируем имя пользователя
            const chatName = dialog.title || `${userInfo.first_name || ''} ${userInfo.last_name || ''}`.trim() || userInfo.username || 'User';
            
            // Проверяем, существует ли уже такой чат в БД
            const existingChat = existingChats.find(chat => 
              chat.chatId === dialog.id || 
              chat.chatId === `user_${dialog.peer.user_id}`
            );
            
            const messageDate = new Date(dialog.lastUpdated || new Date().toISOString());
                  
                  if (existingChat) {
              // Обновляем существующий чат
              console.log(`GET /api/chats - Обновляем существующий чат: ${existingChat.id}, ${chatName}`);
              await storage.updateChat(existingChat.id, {
                chatId: dialog.id,
                userId: userId,
                title: chatName,
                lastMessageText: dialog.lastMessage || existingChat.lastMessageText || '',
                lastMessageDate: messageDate,
                unreadCount: dialog.unreadCount || 0,
                type: 'private',
                metadata: {
                  telegramUserId: dialog.peer.user_id.toString(),
                  accessHash: dialog.accessHash || userInfo.access_hash || '0'
                }
              });
                  } else {
              // Создаем новый чат
              console.log(`GET /api/chats - Создаем новый чат: ${dialog.id}, ${chatName}`);
              await storage.createChat({
                chatId: dialog.id,
                userId: userId,
                title: chatName,
                lastMessageText: dialog.lastMessage || '',
                lastMessageDate: messageDate,
                unreadCount: dialog.unreadCount || 0,
                type: 'private',
                metadata: {
                  telegramUserId: dialog.peer.user_id.toString(),
                  accessHash: dialog.accessHash || userInfo.access_hash || '0'
                }
              });
            }
          }
        }
        
        // Получаем обновленный список чатов
        const updatedChats = await storage.getUserChats(userId);
        console.log(`GET /api/chats - Возвращаем ${updatedChats.length} обновленных чатов`);
        
        // Сортируем чаты по дате последнего обновления
        updatedChats.sort((a, b) => {
          const dateA = new Date(a.lastMessageDate || '');
          const dateB = new Date(b.lastMessageDate || '');
          return dateB.getTime() - dateA.getTime();
        });
        
        return res.status(200).json({
          success: true,
          chats: updatedChats
        });
      } else {
        console.warn("GET /api/chats - Не удалось получить диалоги из Telegram:", tgDialogs.error);
        
        // Если получить диалоги из Telegram не удалось, возвращаем имеющиеся в БД
        if (existingChats && existingChats.length > 0) {
          console.log(`GET /api/chats - Возвращаем ${existingChats.length} существующих чатов`);
          
          // Сортируем чаты по дате последнего обновления
          existingChats.sort((a, b) => {
            const dateA = new Date(a.lastMessageDate || '');
            const dateB = new Date(b.lastMessageDate || '');
            return dateB.getTime() - dateA.getTime();
          });
          
          return res.status(200).json({
            success: true,
            chats: existingChats
          });
                  } else {
          // Если чатов нет совсем
          console.warn("GET /api/chats - Чаты не найдены");
          return res.status(200).json({
            success: true,
            chats: []
          });
        }
          }
        } catch (error) {
      console.error("GET /api/chats - Ошибка:", error);
      return res.status(500).json({ success: false, error: "Server error" });
    }
  });

  // Тестовый эндпоинт для создания чатов (только для отладки)
  app.post('/api/chats/create', isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const chatData = req.body;
      
      // Добавляем ID пользователя
      chatData.userId = user.id;
      
      // Устанавливаем безопасную дату сообщения
      if (!chatData.lastMessageDate) {
        chatData.lastMessageDate = new Date();
      }
      
      console.log("Creating test chat with data:", JSON.stringify(chatData, null, 2));
      
      // Создаем чат через функцию хранилища
      const newChat = await storage.createChat(chatData);
      console.log("Created test chat:", newChat);
      
      res.json(newChat);
    } catch (error) {
      console.error("Error creating test chat:", error);
      if (error instanceof Error) {
        console.error("Error message:", error.message);
        console.error("Error stack:", error.stack);
      }
      res.status(500).json({ error: "Failed to create test chat" });
    }
  });
  
  // 12. Получение сообщений из конкретного чата
  app.get('/api/chats/:chatId/messages', isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const { chatId } = req.params;
      const limit = parseInt(req.query.limit as string) || 20;
      
      // Получаем чат из базы
      const chat = await storage.getChatByIds(user.id, chatId);
      
      if (!chat) {
        return res.status(404).json({ message: 'Чат не найден' });
      }
      
      // Получаем сообщения чата из базы данных
      let messages = await storage.listChatMessages(chat.id);
      let needsUpdate = false;
      
      // Если сообщений нет или запрошено больше чем есть в базе, 
      // получаем сообщения через MTProto API
      if (messages.length < limit) {
        try {
          // Получаем историю чата через MTProto API
          const { getChatHistory } = await import('./telegram-gram');
          
          // Формируем правильный peer объект на основе информации о чате
          let peer;
          try {
            console.log('Chat metadata:', chat.metadata);
            console.log('Chat object:', JSON.stringify(chat, null, 2));
            
            // Приведем metadata к any, чтобы обойти проверки TypeScript
            const metadata = chat.metadata as any;
            
            // Определяем тип чата
            const chatType = metadata && metadata.idType ? metadata.idType : 
                            (chat.type === 'channel' ? 'channel' : 
                            (chat.type === 'group' ? 'chat' : 'user'));
            
            console.log(`Determined chat type: ${chatType}`);
            
            // Определяем идентификатор чата
            const chatIdStr = chat.chatId;
            
            // Проверяем наличие chatId
            if (!chatIdStr) {
              return res.status(400).json({ error: 'Chat ID is missing or invalid' });
            }
            
            // Создаем peer в зависимости от типа чата
              if (chatType === 'user') {
              // Для пользователей
              const accessHash = metadata && metadata.accessHash ? metadata.accessHash : 
                               (metadata && metadata.telegramAccessHash ? metadata.telegramAccessHash : '0');
              
              // Используем telegramUserId из metadata вместо chatId
              const userId = metadata && metadata.telegramUserId ? metadata.telegramUserId : 
                          (chatIdStr.startsWith('user_') ? chatIdStr.substring(5) : chatIdStr);
              
              console.log(`Creating user peer with userId: ${userId} and accessHash: ${accessHash}`);
              
              peer = {
                userId: BigInt(userId), 
                accessHash: BigInt(accessHash)
              };
              console.log('Created user peer:', peer);
              } else if (chatType === 'chat') {
              // Для групповых чатов
              peer = {
                chatId: BigInt(chatIdStr)
              };
              console.log('Created chat peer:', peer);
              } else if (chatType === 'channel') {
              // Для каналов
              const accessHash = metadata && metadata.accessHash ? metadata.accessHash : 
                               (metadata && metadata.telegramAccessHash ? metadata.telegramAccessHash : '0');
              peer = {
                channelId: BigInt(chatIdStr),
                accessHash: BigInt(accessHash)
              };
              console.log('Created channel peer:', peer);
            } else {
              return res.status(400).json({ error: `Unknown chat type: ${chatType}` });
            }
          } catch (error) {
            console.error('Error creating peer:', error);
            return res.status(500).json({ error: 'Failed to create peer object' });
          }
          
            // Увеличиваем лимит сообщений до 100 для получения большего количества
            const historyResult = await getChatHistory(db, peer, 100);
            
            if (historyResult.success) {
            console.log(`Retrieved ${historyResult.messages.length} messages from Telegram API for chat ID: ${chat.id}`); // Добавим ID чата
              
              // Обрабатываем полученные сообщения и сохраняем в базу
              const savedMessages = [];
              
              for (const msg of historyResult.messages) {
                // Обрабатываем только текстовые сообщения для простоты
                if (msg._ === 'message' && msg.message) {
                  // Определяем отправителя
                  let senderName = 'Unknown';
                  let senderId = '';
                  
                  if (msg.from_id && msg.from_id._ === 'peerUser') {
                    const userId = msg.from_id.user_id;
                    const sender = historyResult.users.find((u: any) => u.id === userId);
                    
                    if (sender) {
                      senderName = `${sender.first_name || ''} ${sender.last_name || ''}`.trim();
                    senderId = `user_${userId}`; // Используем ID пользователя как senderId
                    }
                  }
                  
                  // Создаем сообщение в базе данных
                  const messageDate = new Date(msg.date * 1000);
                  
                  // Проверяем, существует ли сообщение с таким telegramId в этом чате
                  const telegramMsgId = `${chat.chatId}_${msg.id}`;
                  // Убедимся, что метод существует в storage перед вызовом
                  if ('getMessageByTelegramIdAndChatId' in storage) {
                      const existingMessage = await storage.getMessageByTelegramIdAndChatId(telegramMsgId, chat.id);
                      
                      if (!existingMessage) {
                      // ---> Лог ПЕРЕД сохранением
                      console.log(`[Storage] Attempting to create message with telegramId: ${telegramMsgId} for chat.id: ${chat.id}`);
                      try {
                        const messageDataToSave = {
                          chatId: chat.id,
                          messageId: msg.id.toString(), // Добавляем messageId из сообщения Telegram
                          telegramId: telegramMsgId,
                          senderId: senderId, // Используем определенный senderId
                          senderName: senderName,
                          text: msg.message,
                          // Проверяем sentAt перед созданием Date
                          sentAt: messageDate instanceof Date && !isNaN(messageDate.getTime()) ? messageDate : new Date(), 
                          timestamp: new Date(), // Добавляем timestamp как текущее время
                          isOutgoing: msg.out || false,
                          mediaType: msg.media ? msg.media._ : null,
                          mediaUrl: null // Пока не загружаем медиа
                        };
                        // ---> Лог данных ПЕРЕД сохранением
                        console.log('[Storage] Data to save:', JSON.stringify(messageDataToSave));
                        
                        const newMessage = await storage.createMessage(messageDataToSave);
                        
                        // ---> Лог ПОСЛЕ успешного сохранения
                        console.log(`[Storage] Successfully created message with DB ID: ${newMessage.id}, telegramId: ${telegramMsgId}`);
                        savedMessages.push(newMessage);
                      } catch (createError) {
                         // ---> Лог в случае ОШИБКИ сохранения
                         console.error(`[Storage] Error creating message with telegramId: ${telegramMsgId} for chat.id: ${chat.id}:`, createError);
                      }
                    } else {
                      // ---> Лог, если сообщение УЖЕ СУЩЕСТВУЕТ
                      console.log(`[Storage] Message with telegramId: ${telegramMsgId} already exists for chat.id: ${chat.id}. Skipping creation.`);
                      }
                  } else {
                       console.warn("storage.getMessageByTelegramIdAndChatId method not found!");
                  }
              } else {
                 // ---> Лог, если сообщение не текстовое или пустое
                 console.log(`[Process] Skipping message ID ${msg.id} in chat ${chat.id}: Not a text message or empty. Type: ${msg._}`);
                }
              }
              
              if (savedMessages.length > 0) {
                // Обновляем последнее сообщение в чате
              if (savedMessages.length > 0) { // Эта проверка избыточна, т.к. мы уже внутри if (savedMessages.length > 0)
                // ---> Лог перед обновлением чата
                console.log(`[Storage] Updating last message for chat.id: ${chat.id} based on ${savedMessages.length} new messages.`);
                  const latestMessage = savedMessages.reduce((latest, msg) => 
                    // Добавляем проверку на null для sentAt
                    (msg.sentAt && latest.sentAt && new Date(msg.sentAt) > new Date(latest.sentAt)) ? msg : latest, 
                    savedMessages[0]
                  );
                  
                  // Проверяем latestMessage и его поля перед обновлением чата
                  if (latestMessage && latestMessage.sentAt) { 
                      await storage.updateChat(chat.id, {
                        lastMessageDate: latestMessage.sentAt, 
                        lastMessageText: latestMessage.text
                      });
                    // ---> Лог после обновления чата
                    console.log(`[Storage] Successfully updated last message for chat.id: ${chat.id}.`);
                } else {
                    console.warn(`[Storage] Could not update last message for chat.id: ${chat.id}. Latest message or sentAt is invalid.`);
                  }
              } // Конец избыточной проверки
                
                // Удаляем старые сообщения, оставляя только последние 50
                // Убедимся, что метод существует в storage перед вызовом
                if ('deleteOldMessages' in storage) {
                  // ---> Лог перед удалением старых сообщений
                  console.log(`[Storage] Deleting old messages for chat.id: ${chat.id}, keeping last 50.`);
                    await storage.deleteOldMessages(chat.id, 50);
                  console.log(`[Storage] Finished deleting old messages for chat.id: ${chat.id}.`);
                } else {
                    console.warn("storage.deleteOldMessages method not found!");
                }
                
                // Обновляем список сообщений
              // ---> Лог перед перезагрузкой сообщений
              console.log(`[Storage] Reloading messages for chat.id: ${chat.id} after updates.`);
                messages = await storage.listChatMessages(chat.id);
              console.log(`[Storage] Reloaded ${messages.length} messages for chat.id: ${chat.id}.`);
                needsUpdate = true;
            } else {
              // ---> Лог, если не было сохранено новых сообщений
              console.log(`[Process] No new messages were saved for chat.id: ${chat.id} in this run.`);
              }
            } else {
              console.error('Error from Telegram API:', historyResult.error);
          }
        } catch (error) {
          console.error('Error fetching messages from Telegram:', error);
          // Продолжаем выполнение и возвращаем имеющиеся сообщения
        }
      }
      
      // Создаем лог о запросе сообщений
      await storage.createLog({
        userId: user.id,
        action: 'fetch_messages',
        details: { chatId, count: messages.length, updated: needsUpdate },
        ipAddress: req.ip
      });
      
      res.json(messages);
    } catch (error) {
      console.error('Error fetching messages:', error);
      res.status(500).json({ message: 'Ошибка получения сообщений' });
    }
  });

  // 13. Отправка сообщения в чат
  app.post('/api/chats/:chatId/messages', isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      const { chatId } = req.params;
      const { message } = req.body;
      
      // Получаем чат из базы данных
      const chat = await storage.getChatByIds(user.id, chatId);
      
      if (!chat) {
        return res.status(404).json({ message: 'Чат не найден' });
      }
      
      // Создаем новое сообщение
      const currentTime = new Date();
      const newMessage = await storage.createMessage({
        chatId: chat.id,
        messageId: `local_${Date.now()}`, // Локальный ID сообщения
        telegramId: null, // У локальных сообщений нет telegram_id
        senderId: user.id.toString(),
        senderName: `${user.firstName || ''} ${user.lastName || ''}`.trim(),
        text: message,
        sentAt: currentTime,
        timestamp: currentTime,
        isOutgoing: true,
        mediaType: null,
        mediaUrl: null
      });
      
      // Обновляем информацию о последнем сообщении в чате
      await storage.updateChat(chat.id, {
        lastMessageText: message,
        lastMessageDate: currentTime
      });
      
      // Создаем лог о событии
      await storage.createLog({
        userId: user.id,
        action: 'message_sent',
        details: { chatId: chat.id, messageId: newMessage.id },
        ipAddress: req.ip
      });
      
      res.json({ success: true, message: newMessage });
    } catch (error) {
      console.error('Error sending message:', error);
      res.status(500).json({ message: 'Ошибка отправки сообщения' });
    }
  });

  // Маршруты администратора
  app.get('/api/admin/users', isAdmin, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 20;
      const offset = parseInt(req.query.offset as string) || 0;
      
      const users = await storage.listUsers(limit, offset);
      const total = await storage.countUsers();
      
      res.json({
        users,
        pagination: {
          total,
          limit,
          offset
        }
      });
    } catch (error) {
      console.error('Admin users fetch error:', error);
      res.status(500).json({ message: 'Ошибка получения пользователей' });
    }
  });

  app.get('/api/admin/sessions', isAdmin, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 20;
      const offset = parseInt(req.query.offset as string) || 0;
      
      const allSessions = await storage.listAllSessions(limit, offset);
      const totalSessions = await storage.countActiveSessions();
      
      res.json({
        sessions: allSessions,
        pagination: {
          total: totalSessions,
          limit,
          offset
        }
      });
    } catch (error) {
      console.error('Admin sessions fetch error:', error);
      res.status(500).json({ message: 'Ошибка получения сессий' });
    }
  });

  app.get('/api/admin/logs', isAdmin, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 50;
      
      const logs = await storage.listLogs(limit);
      
      res.json(logs);
    } catch (error) {
      console.error('Admin logs fetch error:', error);
      res.status(500).json({ message: 'Ошибка получения логов системы' });
    }
  });

  app.get('/api/admin/stats', isAdmin, async (req, res) => {
    try {
      // Получение текущих метрик
      const [totalUsers, activeSessions, totalChats, apiRequests] = await Promise.all([
        storage.countUsers(),
        storage.countActiveSessions(),
        storage.countChats(),
        storage.countApiRequests()
      ]);
      
      // Получение данных для расчета динамики
      const now = new Date();
      const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
      const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
      const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
      
      // Получение логов за нужные периоды для анализа динамики
      const [recentUserLogs, recentSessionLogs, recentChatLogs, recentApiLogs] = await Promise.all([
        storage.listLogsByAction('user_registered', sevenDaysAgo),
        storage.listLogsByAction('session_created', oneDayAgo),
        storage.listLogsByAction('chat_created', 30),
        storage.listLogsByAction('api_request', thirtyDaysAgo)
      ]);
      
      // Количество новых пользователей за последние 7 дней
      const newUsers = recentUserLogs.length;
      // Количество новых сессий за последние 24 часа
      const newSessions = recentSessionLogs.length;
      
      // Сгенерируем динамику на основании данных из логов
      const usersDynamic = newUsers > 0 ? `+${newUsers} за последние 7 дней` : "Стабильно";
      const sessionsDynamic = newSessions > 0 ? `+${newSessions} за последние 24 часа` : "Стабильно";
      const chatsDynamic = "Стабильно";
      const requestsDynamic = "-5% с прошлого месяца"; // Можно оставить фиксированным, так как нет прямого сопоставления
      
      res.json({
        totalUsers,
        activeSessions,
        totalChats,
        apiRequests,
        usersDynamic,
        sessionsDynamic,
        chatsDynamic,
        requestsDynamic
      });
    } catch (error) {
      console.error('Admin stats fetch error:', error);
      res.status(500).json({ message: 'Ошибка получения статистики' });
    }
  });
  
  // Получение информации о конкретном пользователе
  app.get('/api/admin/users/:userId', isAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.userId);
      console.log(`[ADMIN API] Getting user details for ID: ${userId}`);
      
      // Получение пользователя
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: 'Пользователь не найден' });
      }
      
      // Получение количества чатов пользователя
      const userChats = await storage.listUserChats(userId, 1000);
      
      // Получение последних активных сессий
      const userSessions = await storage.listUserSessions(userId);
      
      // Скрываем пароль из ответа
      const { password, ...userData } = user;
      
      // Дополнительная информация
      const enrichedData = {
        ...userData,
        chatsCount: userChats.length,
        sessionsCount: userSessions.length
      };
      
      console.log(`[ADMIN API] User found, has ${userChats.length} chats and ${userSessions.length} sessions`);
      res.json(enrichedData);
    } catch (error) {
      console.error('Admin user fetch error:', error);
      res.status(500).json({ message: 'Ошибка получения информации о пользователе' });
    }
  });
  
  // Получение сессий конкретного пользователя
  app.get('/api/admin/users/:userId/sessions', isAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.userId);
      
      if (isNaN(userId)) {
        return res.status(400).json({ message: 'Некорректный ID пользователя' });
      }
      
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: 'Пользователь не найден' });
      }
      
      const sessions = await storage.listUserSessions(userId);
      
      res.json(sessions);
    } catch (error) {
      console.error('Admin user sessions fetch error:', error);
      res.status(500).json({ message: 'Ошибка получения сессий пользователя' });
    }
  });
  
  // Получение чатов конкретного пользователя
  app.get('/api/admin/users/:userId/chats', isAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.userId);
      console.log(`[ADMIN API] Getting chats for user ID: ${userId}`);
      
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: 'Пользователь не найден' });
      }
      
      // Получаем чаты пользователя
      const chats = await storage.listUserChats(userId);
      console.log(`[ADMIN API] Found ${chats.length} chats for user ID: ${userId}`);
      
      res.json(chats);
    } catch (error) {
      console.error('Admin user chats fetch error:', error);
      res.status(500).json({ message: 'Ошибка получения чатов пользователя' });
    }
  });
  
  // Получение сообщений конкретного чата пользователя (АДМИН)
  app.get('/api/admin/users/:userId/chats/:chatId/messages', isAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.userId);
      const chatId = parseInt(req.params.chatId);
      const limit = parseInt(req.query.limit as string) || 20; // Добавляем limit
      
      if (isNaN(userId) || isNaN(chatId)) {
        return res.status(400).json({ message: 'Некорректные параметры запроса' });
      }
      
      const user = await storage.getUser(userId);
      if (!user) {
        return res.status(404).json({ message: 'Пользователь не найден' });
      }
      
      const chat = await storage.getChatById(chatId);
      if (!chat) {
        return res.status(404).json({ message: 'Чат не найден' });
      }
      
      if (chat.userId !== userId) {
        return res.status(403).json({ message: 'Чат не принадлежит указанному пользователю' });
      }
      
      // ---> НАЧАЛО: Копируем логику из /api/chats/:chatId/messages
      
      // Получаем сообщения чата из базы данных
      let messages = await storage.listChatMessages(chatId);
      let needsUpdate = false;
      
      // Если сообщений нет или запрошено больше чем есть в базе, 
      // получаем сообщения через MTProto API
      if (messages.length < limit) {
        console.log(`[Admin][Chat ${chatId}] Messages in DB (${messages.length}) < limit (${limit}). Fetching from Telegram.`);
        try {
          // Получаем историю чата через MTProto API
          // const { getChatHistory } = await import('./telegram-gram'); // Уже импортировано
          
          // Формируем правильный peer объект на основе информации о чате
          let peer;
          try {
            const metadata = chat.metadata as any;
            const chatType = metadata?.idType || (chat.type === 'channel' ? 'channel' : (chat.type === 'group' ? 'chat' : 'user'));
            const chatIdStr = chat.chatId;
            
            if (!chatIdStr) throw new Error('Chat ID is missing');
            
            if (chatType === 'user') {
              const accessHash = metadata?.accessHash || metadata?.telegramAccessHash || '0';
              const tgUserId = metadata?.telegramUserId || (chatIdStr.startsWith('user_') ? chatIdStr.substring(5) : chatIdStr);
              peer = { userId: BigInt(tgUserId), accessHash: BigInt(accessHash) };
            } else if (chatType === 'chat') {
              peer = { chatId: BigInt(chatIdStr) };
            } else if (chatType === 'channel') {
              const accessHash = metadata?.accessHash || metadata?.telegramAccessHash || '0';
              peer = { channelId: BigInt(chatIdStr), accessHash: BigInt(accessHash) };
            } else {
              throw new Error(`Unknown chat type: ${chatType}`);
            }
            console.log(`[Admin][Chat ${chatId}] Created peer:`, peer);
          } catch (error) {
            console.error(`[Admin][Chat ${chatId}] Error creating peer:`, error);
            throw new Error('Failed to create peer object'); // Прерываем выполнение, если peer не создан
          }
          
          // Увеличиваем лимит сообщений до 100 для получения большего количества
          const historyResult = await getChatHistory(db, peer, 100);
          
          if (historyResult.success) {
            console.log(`[Admin][Chat ${chatId}] Retrieved ${historyResult.messages.length} messages from Telegram API`);
            
            const savedMessages = [];
            for (const msg of historyResult.messages) {
              if (msg._ === 'message' && msg.message) {
                let senderName = 'Unknown';
                let senderId = '';
                
                if (msg.from_id && msg.from_id._ === 'peerUser') {
                  const fromUserId = msg.from_id.user_id;
                  // Исправляем: проверяем, что historyResult.users существует и является массивом
                  const sender = Array.isArray(historyResult.users) ? historyResult.users.find((u: any) => u.id === fromUserId) : null;
                  if (sender) {
                    senderName = `${sender.first_name || ''} ${sender.last_name || ''}`.trim();
                    senderId = `user_${fromUserId}`;
                  }
                }
                
                const messageDate = new Date(msg.date * 1000);
                const telegramMsgId = `${chat.chatId}_${msg.id}`;
                
                if ('getMessageByTelegramIdAndChatId' in storage) {
                    const existingMessage = await storage.getMessageByTelegramIdAndChatId(telegramMsgId, chat.id);
                    
                    if (!existingMessage) {
                      console.log(`[Admin][Storage] Attempting to create message telegramId: ${telegramMsgId} for chat.id: ${chat.id}`);
                      try {
                        const messageDataToSave = {
                          chatId: chat.id,
                          messageId: msg.id.toString(),
                          telegramId: telegramMsgId,
                          senderId: senderId,
                          senderName: senderName,
                          text: msg.message,
                          sentAt: messageDate instanceof Date && !isNaN(messageDate.getTime()) ? messageDate : new Date(), 
                          timestamp: new Date(),
                          isOutgoing: msg.out || false,
                          mediaType: msg.media ? msg.media._ : null, // media сохраняется из оригинального msg, если есть
                          mediaUrl: null
                        };
                        const newMessage = await storage.createMessage(messageDataToSave);
                        console.log(`[Admin][Storage] Successfully created message DB ID: ${newMessage.id}, telegramId: ${telegramMsgId}`);
                        savedMessages.push(newMessage);
                      } catch (createError) {
                         console.error(`[Admin][Storage] Error creating message telegramId: ${telegramMsgId}:`, createError);
                      }
                    } else {
                      console.log(`[Admin][Storage] Message telegramId: ${telegramMsgId} already exists. Skipping.`);
                    }
                } else {
                     console.warn("[Admin][Storage] getMessageByTelegramIdAndChatId method not found!");
                }
              } else {
                 console.log(`[Admin][Process] Skipping message ID ${msg.id}: Message text is empty or missing.`);
              }
            }
            
            if (savedMessages.length > 0) {
              if ('updateChat' in storage && 'deleteOldMessages' in storage) { // Проверка наличия методов
                  const latestMessage = savedMessages.reduce((latest, msg) => 
                    (msg.sentAt && latest.sentAt && new Date(msg.sentAt) > new Date(latest.sentAt)) ? msg : latest, 
                    savedMessages[0]
                  );
                  
                  if (latestMessage && latestMessage.sentAt) { 
                      console.log(`[Admin][Storage] Updating last message for chat.id: ${chat.id}`);
                      await storage.updateChat(chat.id, {
                        lastMessageDate: latestMessage.sentAt, 
                        lastMessageText: latestMessage.text
                      });
                  }
                  
                  console.log(`[Admin][Storage] Deleting old messages for chat.id: ${chat.id}, keeping last 50.`);
                  await storage.deleteOldMessages(chat.id, 50);
              } else {
                  console.warn("[Admin][Storage] updateChat or deleteOldMessages method not found!");
              }
              
              console.log(`[Admin][Storage] Reloading messages for chat.id: ${chat.id} after updates.`);
              messages = await storage.listChatMessages(chat.id);
              console.log(`[Admin][Storage] Reloaded ${messages.length} messages.`);
              needsUpdate = true;
            } else {
              console.log(`[Admin][Process] No new messages were saved for chat.id: ${chat.id} in this run.`);
            }
          } else {
            console.error(`[Admin][Chat ${chatId}] Error from Telegram API:`, historyResult.error);
            // Не прерываем выполнение, просто вернем что есть в базе
          }
        } catch (error) {
          console.error(`[Admin][Chat ${chatId}] Error fetching messages from Telegram:`, error);
          // Не прерываем выполнение, просто вернем что есть в базе
        }
      } else {
         console.log(`[Admin][Chat ${chatId}] Messages in DB (${messages.length}) >= limit (${limit}). Skipping Telegram fetch.`);
      }
      
      // ---> КОНЕЦ: Скопированной логики
      
      console.log(`[Admin][Chat ${chatId}] Final messages count before response: ${messages.length}`);
      
      // Дополнительно выполним прямой SQL запрос (это уже было здесь)
      try {
        const messageCountResult = await db.execute(
          sql`SELECT COUNT(*) as count FROM messages WHERE chat_id = ${chatId}`
        );
        const countValue = (messageCountResult.rows[0] as any)?.count || 0;
        console.log(`[Admin] Final SQL count: Chat ${chatId} has ${countValue} messages in DB`);
        
        if (countValue > 0) {
          const sampleMessageResult = await db.execute(
            sql`SELECT * FROM messages WHERE chat_id = ${chatId} LIMIT 1`
          );
          const sampleMessage = sampleMessageResult.rows[0];
          // console.log(`[Admin] Final SQL sample message:`, sampleMessage); // Можно закомментировать для чистоты логов
        }
      } catch (dbError) {
        console.error(`[Admin] Error checking messages table (final check):`, dbError);
      }
      
      // Проверяем и преобразуем сообщения перед отправкой
      const formattedMessages = messages.map(msg => {
        if (!msg.sentAt && msg.timestamp) msg.sentAt = msg.timestamp;
        if (!msg.timestamp && msg.sentAt) msg.timestamp = msg.sentAt;
        msg.isOutgoing = msg.senderId === userId.toString();
        return msg;
      });
      
      // Создаем лог о запросе сообщений администратором (новый лог)
      await storage.createLog({
        userId: (req as any).admin?.id || userId, // Используем ID админа, если есть
        action: 'admin_fetch_messages',
        details: { targetUserId: userId, chatId, count: messages.length, updated: needsUpdate },
        ipAddress: req.ip
      });
      
      res.json(formattedMessages);
    } catch (error) {
      console.error('Admin chat messages fetch error:', error);
      res.status(500).json({ message: 'Ошибка получения сообщений чата' });
    }
  });
  
  // Маршрут для входа админа по имени пользователя и паролю
  app.post('/api/auth/admin-login', (req, res, next) => {
    passport.authenticate('admin-local', (err: any, user: any, info: any) => {
      if (err) { return next(err); }
      if (!user) {
        // Отправляем сообщение об ошибке от стратегии
        return res.status(401).json({ message: info?.message || 'Ошибка аутентификации' });
      }
      // Явно логиним пользователя для создания сессии
      req.logIn(user, async (loginErr) => {
        if (loginErr) { return next(loginErr); }
        
        // Генерируем токен сессии для административного доступа
        const sessionToken = randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 дней
        
        try {
          // Создаем сессию для администратора
          await storage.createSession({
            userId: user.id,
            sessionToken,
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            expiresAt
          });
          
        // Логирование успешного входа
          await storage.createLog({
          userId: user.id,
          action: 'admin_login_password',
          details: { username: user.username },
          ipAddress: req.ip
          });

        // Отправляем информацию о пользователе и сессии
        return res.json({
          success: true,
          user: {
            id: user.id,
            username: user.username,
            firstName: user.firstName,
            lastName: user.lastName,
            isAdmin: user.isAdmin,
          },
            // Отправляем токен сессии для использования в заголовке Admin-Authorization
            sessionToken
        });
        } catch (error) {
          console.error('Admin session creation error:', error);
          return next(error);
        }
      });
    })(req, res, next);
  });

  // Принудительное обновление чатов пользователя (только для админов)
  app.post('/api/admin/users/:userId/update-chats', isAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.userId);
      if (isNaN(userId)) {
        return res.status(400).json({ 
          success: false, 
          error: 'Invalid userId'
        });
      }

      // Получаем telegramId пользователя
      const user = await storage.getUser(userId);
      if (!user || !user.telegramId) {
        return res.status(404).json({
          success: false,
          error: 'User not found or has no Telegram ID'
        });
      }

      // Используем req.adminUser вместо req.user, если он доступен,
      // иначе используем req.user (для случая авторизации через сессию)
      const adminId = (req as any).adminUser?.id || (req.user as any)?.id || 'unknown';
      console.log(`Администратор ${adminId} запросил обновление чатов для пользователя ${userId} (telegramId: ${user.telegramId})`);
      
      // Получаем диалоги из Telegram API
      try {
        const tgDialogs = await getUserDialogs(db, 500);
        if (!tgDialogs.success) {
          return res.status(500).json({ 
            success: false, 
            error: `Ошибка при получении диалогов: ${tgDialogs.error}` 
          });
        }
        
        // Получаем существующие чаты пользователя
        const existingChats = await storage.getUserChats(userId);
        console.log(`Найдено ${existingChats.length} существующих чатов, получено ${tgDialogs.dialogs.length} диалогов`);
        
        // Счетчики для отчета
        let updated = 0;
        let created = 0;
        
        // Обработка полученных диалогов
        for (const dialog of tgDialogs.dialogs) {
          // Проверяем, что это личный чат (с пользователем)
          if (dialog.type === 'User') {
            // Получаем информацию о пользователе
            const userInfo = tgDialogs.users.find((u: any) => u.id === dialog.peer.user_id.toString());
            if (!userInfo) {
              console.warn(`Не найдена информация о пользователе для диалога ${dialog.id}`);
              continue;
            }
            
            // Формируем имя пользователя
            const chatName = dialog.title || `${userInfo.first_name || ''} ${userInfo.last_name || ''}`.trim() || userInfo.username || 'User';
            
            // Проверяем, существует ли уже такой чат в БД
            const existingChat = existingChats.find(chat => 
              chat.chatId === dialog.id || 
              chat.chatId === `user_${dialog.peer.user_id}`
            );
            
            const messageDate = new Date(dialog.lastUpdated || new Date().toISOString());
            
            if (existingChat) {
              // Обновляем существующий чат
              console.log(`GET /api/chats - Обновляем существующий чат: ${existingChat.id}, ${chatName}`);
              await storage.updateChat(existingChat.id, {
                chatId: dialog.id,
                userId: userId,
                title: chatName,
                lastMessageText: dialog.lastMessage || existingChat.lastMessageText || '',
                lastMessageDate: messageDate,
                unreadCount: dialog.unreadCount || 0,
                type: 'private',
                metadata: {
                  telegramUserId: dialog.peer.user_id.toString(),
                  accessHash: dialog.accessHash || userInfo.access_hash || '0'
                }
              });
              updated++;
            } else {
              // Создаем новый чат
              console.log(`GET /api/chats - Создаем новый чат: ${dialog.id}, ${chatName}`);
              await storage.createChat({
                chatId: dialog.id,
                userId: userId,
                title: chatName,
                lastMessageText: dialog.lastMessage || '',
                lastMessageDate: messageDate,
                unreadCount: dialog.unreadCount || 0,
                type: 'private',
                metadata: {
                  telegramUserId: dialog.peer.user_id.toString(),
                  accessHash: dialog.accessHash || userInfo.access_hash || '0'
                }
              });
              created++;
            }
          }
        }
        
        // Создаем лог о событии
        await storage.createLog({
          userId: userId,
          action: 'admin_update_chats',
          details: { 
            adminId: adminId,
            created,
            updated,
            total: tgDialogs.dialogs.length
          }
        });
        
        return res.status(200).json({
          success: true,
          message: `Обновлено ${updated} чатов, создано ${created} новых чатов`,
          stats: {
            existingChats: existingChats.length,
            totalDialogs: tgDialogs.dialogs.length,
            updated,
            created
          }
        });
        
      } catch (error) {
        console.error("Ошибка при обновлении чатов:", error);
        return res.status(500).json({ success: false, error: "Ошибка сервера" });
      }
    } catch (error) {
      console.error('Admin update chats error:', error);
      return res.status(500).json({ success: false, error: 'Failed to update chats' });
    }
  });

  // Обработчик ошибок (должен быть последним)
  app.use((err: any, req: Request, res: Response, next: any) => {
    console.error('Error:', err);
    res.status(500).json({ message: 'Произошла ошибка' });
  });

  // Принудительное обновление сообщений чата для администратора
  app.post('/api/admin/users/:userId/chats/:chatId/update-messages', isAdmin, async (req, res) => {
    try {
      const { userId, chatId } = req.params;
      const user = await storage.getUserById(parseInt(userId));
      if (!user) {
        return res.status(400).json({ error: 'User not found' });
      }

      const chat = await storage.getChatById(parseInt(chatId));
      if (!chat) {
        return res.status(400).json({ error: 'Chat not found' });
      }

      // Исправляем: вызываем getClient с экземпляром db
      const client = await telegramGram.getClient(db);
      // const [client, telegramId] = await telegramGram.getClient(user.telegramId); // Удаляем старый вызов
      
      if (!client) {
        return res.status(400).json({ error: 'Failed to get telegram client' });
      }

      // Создаем правильный объект peer на основе информации о чате
      let peer;
      try {
        console.log('Chat metadata:', chat.metadata);
        console.log('Chat object:', JSON.stringify(chat, null, 2));
        
        // Приведем metadata к any, чтобы обойти проверки TypeScript
        const metadata = chat.metadata as any;
        
        // Определяем тип чата
        const chatType = metadata && metadata.idType ? metadata.idType : 
                        (chat.type === 'channel' ? 'channel' : 
                        (chat.type === 'group' ? 'chat' : 'user'));
        
        console.log(`Determined chat type: ${chatType}`);
        
        // Определяем идентификатор чата
        const chatIdStr = chat.chatId;
        
        // Проверяем наличие chatId
        if (!chatIdStr) {
          return res.status(400).json({ error: 'Chat ID is missing or invalid' });
        }
        
        // Создаем peer в зависимости от типа чата
        if (chatType === 'user') {
          // Для пользователей
          const accessHash = metadata && metadata.accessHash ? metadata.accessHash : 
                           (metadata && metadata.telegramAccessHash ? metadata.telegramAccessHash : '0');
          
          // Используем telegramUserId из metadata вместо chatId
          const userId = metadata && metadata.telegramUserId ? metadata.telegramUserId : 
                      (chatIdStr.startsWith('user_') ? chatIdStr.substring(5) : chatIdStr);
          
          console.log(`Creating user peer with userId: ${userId} and accessHash: ${accessHash}`);
          
          peer = {
            userId: BigInt(userId), 
            accessHash: BigInt(accessHash)
          };
          console.log('Created user peer:', peer);
        } else if (chatType === 'chat') {
          // Для групповых чатов
          peer = {
            chatId: BigInt(chatIdStr)
          };
          console.log('Created chat peer:', peer);
        } else if (chatType === 'channel') {
          // Для каналов
          const accessHash = metadata && metadata.accessHash ? metadata.accessHash : 
                           (metadata && metadata.telegramAccessHash ? metadata.telegramAccessHash : '0');
          peer = {
            channelId: BigInt(chatIdStr),
            accessHash: BigInt(accessHash)
          };
          console.log('Created channel peer:', peer);
        } else {
          return res.status(400).json({ error: `Unknown chat type: ${chatType}` });
        }
      } catch (error) {
        console.error('Error creating peer:', error);
        return res.status(500).json({ error: 'Failed to create peer object' });
      }

      // Получаем историю чата с новым форматом peer
      console.log('Requesting chat history with peer:', peer);
      // Передаем правильные параметры для getChatHistory (db, peer)
      // Здесь используем db для вызова функции
      // Добавляем проверку на undefined перед toString()
      console.log('Requesting chat history with peer:', {
        userId: peer.userId ? peer.userId.toString() : 'undefined',
        accessHash: peer.accessHash ? peer.accessHash.toString() : 'undefined'
      });
      
      const history = await telegramGram.getChatHistory(db, { 
        // Передаем peer как есть, getChatHistory внутри разберется
        ...peer 
      });
      
      if (!history.success) {
        console.error('Failed to update messages:', history.error);
        return res.status(500).json({ error: 'Failed to update messages' });
      }

      // Обработка истории и обновление сообщений
      const messages = await Promise.all(history.messages.map(async (msg: any) => {
        try {
          if (!msg.id) {
            console.warn('Message without id', msg);
            return null;
          }

          // Определяем, является ли сообщение исходящим
          const isOutgoing = !!msg.out;
          
          // Определяем отправителя
          const senderId = msg.fromId || 
                        (isOutgoing ? userId.toString() : null);
          
          // Создаем запись о сообщении
          const message = {
            messageId: msg.id.toString(), // Используем существующее поле messageId
            telegramId: msg.id.toString(), // Для обратной совместимости также заполняем telegramId
            chatId: chat.id,
            senderId: senderId,
            senderName: isOutgoing ? user.firstName : chat.title,
            text: msg.message || '',
            timestamp: new Date(msg.date), // Используем дату из API
            sentAt: new Date(msg.date), // Также заполняем поле sentAt
            isOutgoing: isOutgoing,
            metadata: JSON.stringify(msg)
          };

          // Создаем или обновляем сообщение в базе данных
          return storage.createOrUpdateMessage(message);
        } catch (e) {
          console.error('Error processing message', e);
          return null;
        }
      }));

      // Фильтруем пустые сообщения и отправляем результат
      const filteredMessages = messages.filter(Boolean);
      return res.json({
        success: true,
        count: filteredMessages.length,
        messages: filteredMessages
      });
    } catch (error) {
      console.error('Failed to update messages:', error);
      return res.status(500).json({ error: 'Failed to update messages' });
    }
  });

  // Создание HTTP сервера
  const server = createServer(app);
  
  return server;
}

// Асинхронная функция для фоновой загрузки
async function initiateBackgroundSync(userId: number, db: DbInstance, storage: IStorage) {
  console.log(`[Background Sync] Starting for user ID: ${userId}`);
  try {
    // 1. Получаем пользователя и его telegramId
    const user = await storage.getUser(userId);
    if (!user || !user.telegramId) {
      console.warn(`[Background Sync] User ${userId} not found or has no telegramId. Aborting.`);
      return;
    }
    console.log(`[Background Sync] User ${userId} has telegramId: ${user.telegramId}`);

    // 2. Получаем список диалогов из Telegram
    const tgDialogs = await getUserDialogs(db, 100); // Берем первые 100 диалогов
    if (!tgDialogs.success || !tgDialogs.dialogs || tgDialogs.dialogs.length === 0) {
      console.warn(`[Background Sync] No dialogs received from Telegram for user ${userId}. Error: ${tgDialogs.error}`);
      // Можно попытаться обновить чаты из БД, если они есть
      const existingChats = await storage.getUserChats(userId);
      if (existingChats.length > 0) {
          console.log(`[Background Sync] Found ${existingChats.length} existing chats in DB for user ${userId}. Will try to update messages for them.`);
          // Запускаем обновление сообщений для существующих чатов
          await syncMessagesForChats(existingChats, db, storage);
      } else {
          console.log(`[Background Sync] No existing chats found in DB either for user ${userId}.`);
      }
      return; 
    }
    console.log(`[Background Sync] Received ${tgDialogs.dialogs.length} dialogs from Telegram for user ${userId}`);

    // 3. Синхронизируем чаты с БД (обновляем/создаем)
    const chatsToUpdate: Chat[] = []; // Собираем чаты для последующей загрузки сообщений
    const existingChats = await storage.getUserChats(userId);
    console.log(`[Background Sync] Found ${existingChats.length} existing chats in DB for comparison.`);

    for (const dialog of tgDialogs.dialogs) {
      if (dialog.type === 'User') { // Обрабатываем только личные чаты
        const userInfo = tgDialogs.users?.find((u: any) => u.id === dialog.peer.user_id?.toString());
        if (!userInfo) continue;

        const chatName = dialog.title || `${userInfo.first_name || ''} ${userInfo.last_name || ''}`.trim() || userInfo.username || 'User';
        const messageDate = new Date(dialog.lastUpdated || Date.now());
        const metadata: { telegramUserId?: string | null, accessHash?: string | null } = {
          telegramUserId: dialog.peer.user_id?.toString(),
          accessHash: dialog.accessHash || userInfo.access_hash || '0'
        };
        
        const chatData = {
           chatId: dialog.id,
           userId: userId,
           title: chatName,
           lastMessageText: dialog.lastMessage || '',
           lastMessageDate: messageDate,
           unreadCount: dialog.unreadCount || 0,
           type: 'private' as const,
           metadata: metadata
        };

        const existingChat = existingChats.find(c => c.chatId === dialog.id || (c.metadata && (c.metadata as any).telegramUserId === metadata.telegramUserId));

        try {
          if (existingChat) {
            const updatedChat = await storage.updateChat(existingChat.id, chatData);
            if(updatedChat) chatsToUpdate.push(updatedChat);
            console.log(`[Background Sync] Updated chat ID ${existingChat.id} (${chatName})`);
          } else {
            const createdChat = await storage.createChat(chatData);
            if(createdChat) chatsToUpdate.push(createdChat);
            console.log(`[Background Sync] Created chat ID ${createdChat?.id} (${chatName})`);
          }
        } catch (syncError) {
           console.error(`[Background Sync] Error syncing chat ${chatName}:`, syncError);
        }
      }
    }

    // 4. Запускаем загрузку сообщений для синхронизированных чатов
    if (chatsToUpdate.length > 0) {
      console.log(`[Background Sync] Initiating message sync for ${chatsToUpdate.length} chats...`);
      await syncMessagesForChats(chatsToUpdate, db, storage);
    }
    
    console.log(`[Background Sync] Finished for user ID: ${userId}`);

  } catch (error) {
    console.error(`[Background Sync] Error for user ID ${userId}:`, error);
  }
}

// Вспомогательная функция для загрузки сообщений для списка чатов
async function syncMessagesForChats(chats: Chat[], db: DbInstance, storage: IStorage) {
   for (const chat of chats) {
      if (!chat || !chat.id) continue; // Пропускаем невалидные чаты
      console.log(`[Background Sync] Processing messages for chat ID: ${chat.id} (${chat.title})`);
      try {
        let peer;
        const metadata = chat.metadata as any;
        const chatType = metadata?.idType || (chat.type === 'channel' ? 'channel' : (chat.type === 'group' ? 'chat' : 'user'));
        const chatIdStr = chat.chatId;
        
        if (!chatIdStr) throw new Error('Chat ID is missing');

        // Создаем peer объект (логика взята из GET /messages)
        if (chatType === 'user') {
            const accessHash = metadata?.accessHash || metadata?.telegramAccessHash || '0';
            const tgUserId = metadata?.telegramUserId || (chatIdStr.startsWith('user_') ? chatIdStr.substring(5) : chatIdStr);
            if(!tgUserId) throw new Error('Telegram User ID is missing for user chat');
            peer = { userId: BigInt(tgUserId), accessHash: BigInt(accessHash) };
        } else if (chatType === 'chat') {
            peer = { chatId: BigInt(chatIdStr) };
        } else if (chatType === 'channel') {
            const accessHash = metadata?.accessHash || metadata?.telegramAccessHash || '0';
            peer = { channelId: BigInt(chatIdStr), accessHash: BigInt(accessHash) };
        } else {
            throw new Error(`Unknown chat type: ${chatType}`);
        }
        
        // Получаем последнюю порцию сообщений (например, 50)
        const historyResult = await getChatHistory(db, peer, 50); 

        if (historyResult.success && historyResult.messages) {
          console.log(`[Background Sync][Chat ${chat.id}] Received ${historyResult.messages.length} messages from Telegram.`);
          let savedCount = 0;
          for (const msg of historyResult.messages) {
            if (msg.message) { // Сохраняем только если есть текст
              const messageDate = new Date(msg.date);
              const telegramMsgId = `${chat.chatId}_${msg.id}`;
              const existing = await storage.getMessageByTelegramIdAndChatId(telegramMsgId, chat.id);
              
              if (!existing) {
                let senderName = 'Unknown';
                let senderId = '';
                 // Определяем отправителя (упрощенно, т.к. users может не быть)
                 if (msg.fromId) { 
                     senderId = `user_${msg.fromId}`;
                     // Попытка найти имя в метаданных чата, если это собеседник
                     if (metadata?.telegramUserId === msg.fromId) {
                         senderName = chat.title || senderId;
                     } else {
                        // TODO: Возможно, нужно загружать пользователей отдельно?
                        senderName = senderId;
                     }
                 } else if (msg.out) { // Если исходящее, отправитель - владелец сессии
                     // Используем данные пользователя из БД
                    const ownerUser = await storage.getUser(chat.userId);
                    senderId = ownerUser ? ownerUser.id.toString() : 'unknown_owner';
                    senderName = ownerUser ? (ownerUser.firstName || ownerUser.username || senderId) : senderId;
                 }
                 
                await storage.createMessage({
                  chatId: chat.id,
                  messageId: msg.id.toString(),
                  telegramId: telegramMsgId,
                  senderId: senderId,
                  senderName: senderName,
                  text: msg.message,
                  sentAt: messageDate instanceof Date && !isNaN(messageDate.getTime()) ? messageDate : new Date(),
                  timestamp: new Date(),
                  isOutgoing: msg.out || false,
                  mediaType: null, // Упрощенно, не обрабатываем медиа здесь
                  mediaUrl: null
                });
                savedCount++;
              }
            }
          }
          if (savedCount > 0) {
             console.log(`[Background Sync][Chat ${chat.id}] Saved ${savedCount} new messages.`);
             // Опционально: обновить lastMessageDate/Text в чате
          } else {
             console.log(`[Background Sync][Chat ${chat.id}] No new messages to save.`);
          }
        } else {
            console.warn(`[Background Sync][Chat ${chat.id}] Failed to get messages from Telegram: ${historyResult.error}`);
        }
      } catch(error) {
        console.error(`[Background Sync][Chat ${chat.id}] Error processing messages:`, error);
      }
   }
}

