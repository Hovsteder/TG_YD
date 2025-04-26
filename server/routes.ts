import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { validateTelegramAuth, generateTwoFACode, verifyTwoFACode, getUserChats } from "./telegram";
import { generateVerificationCode, verifyCode, sendVerificationTelegram } from "./phone-auth";
// import { sendAuthCode, verifyAuthCode, signUpNewUser, check2FAPassword, logoutTelegramUser, initTelegramAuth } from "./telegram-auth";
import { 
  sendAuthCode, 
  verifyAuthCode, 
  signUpNewUser, 
  check2FAPassword, 
  logoutTelegramUser, 
  initTelegramAuth,
  createQRLoginCode,
  checkQRLoginStatus
} from "./telegram-gram";
import { z } from "zod";
import { randomBytes, scrypt, timingSafeEqual } from "crypto";
import { promisify } from "util";
import session from "express-session";
import { insertUserSchema, insertSessionSchema, messages, sessions, chats } from "@shared/schema";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { db } from "./db";
import { eq, count } from "drizzle-orm";



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

export async function registerRoutes(app: Express): Promise<Server> {
  // Эндпоинт для проверки работоспособности приложения
  app.get('/api/health', (req, res) => {
    res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
  });
  
  // Настройка сессий
  app.use(session({
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

  // Middleware для проверки аутентификации
  const isAuthenticated = (req: Request, res: Response, next: any) => {
    if (req.isAuthenticated()) {
      return next();
    }
    res.status(401).json({ message: 'Не авторизован' });
  };

  // Middleware для проверки прав администратора
  const isAdmin = (req: Request, res: Response, next: any) => {
    // Проверка авторизации через заголовок Admin-Authorization
    const adminToken = req.headers['admin-authorization'] as string;
    
    if (adminToken) {
      // Проверяем токен администратора
      storage.getSession(adminToken)
        .then(session => {
          if (session) {
            // Получаем данные пользователя по ID из сессии
            return storage.getUser(session.userId);
          }
          return null;
        })
        .then(user => {
          if (user && user.isAdmin) {
            (req as any).adminUser = user;
            next();
          } else {
            res.status(403).json({ message: 'Доступ запрещен' });
          }
        })
        .catch(err => {
          console.error('Admin auth error:', err);
          res.status(500).json({ message: 'Ошибка авторизации' });
        });
      return;
    }
    
    // Проверка обычной авторизации через сессию
    if (req.isAuthenticated() && req.user && (req.user as any).isAdmin) {
      return next();
    }
    
    // Временно отключена проверка на администратора (для тестирования)
    // return next();
    
    res.status(403).json({ message: 'Доступ запрещен' });
  };

  // API маршруты
  // 1. Telegram авторизация
  app.post('/api/auth/telegram', async (req, res) => {
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

  // 2. Проверка 2FA кода
  app.post('/api/auth/verify-2fa', async (req, res) => {
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

  // 3. Повторная отправка 2FA кода
  app.post('/api/auth/resend-2fa', async (req, res) => {
    try {
      const { telegramId } = req.body;
      
      if (!telegramId) {
        return res.status(400).json({ message: 'Отсутствует Telegram ID' });
      }

      // Проверяем существование пользователя
      const user = await storage.getUserByTelegramId(telegramId);
      
      if (!user) {
        return res.status(404).json({ message: 'Пользователь не найден' });
      }

      // Генерируем и отправляем новый код
      await generateTwoFACode(telegramId);

      res.json({
        success: true,
        message: 'Код подтверждения отправлен повторно'
      });
    } catch (error) {
      console.error('Resend 2FA error:', error);
      res.status(500).json({ message: 'Ошибка отправки кода' });
    }
  });

  // === НОВАЯ СИСТЕМА АВТОРИЗАЦИИ ПО ТЕЛЕФОНУ ЧЕРЕЗ API TELEGRAM ===

  // 1. Запрос кода подтверждения по телефону
  app.post('/api/auth/phone/request-code', async (req, res) => {
    try {
      const { phoneNumber } = requestPhoneCodeSchema.parse(req.body);
      
      // Отправляем запрос на получение кода через Telegram API
      const result = await sendAuthCode(phoneNumber);
      
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
        message: 'Код подтверждения отправлен через Telegram',
        phoneCodeHash: result.phoneCodeHash,
        expiresIn: result.timeout || 600, // по умолчанию 10 минут
        codeDeliveryType: 'app' // По умолчанию через приложение
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
  
  // 2. Проверка кода подтверждения по телефону и регистрация пользователя
  app.post('/api/auth/phone/verify-code', async (req, res) => {
    try {
      const { phoneNumber, code } = verifyPhoneCodeSchema.parse(req.body);
      
      // Проверка кода через Telegram API
      const verifyResult = await verifyAuthCode(phoneNumber, code);
      
      if (!verifyResult.success) {
        return res.status(400).json({ 
          success: false, 
          message: verifyResult.error || 'Неверный код или истек срок действия' 
        });
      }
      
      // Проверяем, требуется ли регистрация нового пользователя
      if (verifyResult.requireSignUp) {
        return res.json({
          success: true,
          requireSignUp: true,
          phoneNumber,
          phoneCodeHash: verifyResult.phoneCodeHash
        });
      }
      
      // Проверяем, требуется ли 2FA
      if (verifyResult.require2FA) {
        return res.json({
          success: true,
          require2FA: true,
          phoneNumber,
          phoneCodeHash: verifyResult.phoneCodeHash
        });
      }
      
      // Проверяем, существует ли пользователь с таким телефоном
      let user = await storage.getUserByPhoneNumber(phoneNumber);
      
      if (user) {
        // Пользователь существует, обновляем его данные
        user = await storage.updateUser(user.id, {
          isVerified: true,
          verificationCode: null,
          verificationCodeExpires: null,
          lastLogin: new Date()
        }) || user;
        
        // Создаем лог о входе
        await storage.createLog({
          userId: user.id,
          action: 'user_login',
          details: { phoneNumber },
          ipAddress: req.ip
        });
        
        // Проверяем, установлен ли пароль
        if (!user.password) {
          return res.json({
            success: true,
            requirePassword: true,
            isNewUser: false,
            phoneNumber
          });
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
            return res.status(500).json({ 
              success: false,
              message: 'Ошибка авторизации' 
            });
          }
          
          // Возвращаем данные пользователя и токен сессии
          return res.json({
            success: true,
            user: {
              id: user?.id,
              phoneNumber: user?.phoneNumber,
              username: user?.username,
              firstName: user?.firstName,
              lastName: user?.lastName,
              isAdmin: user?.isAdmin
            },
            sessionToken
          });
        });
      } else {
        // Пользователя нет, нужно создать нового на основе данных от Telegram
        const telegramUser = verifyResult.user;
        
        if (!telegramUser) {
          return res.status(500).json({ 
            success: false,
            message: 'Не удалось получить данные пользователя' 
          });
        }
        
        // Создаем нового пользователя
        user = await storage.createUser({
          phoneNumber,
          firstName: telegramUser.firstName || null,
          lastName: telegramUser.lastName || null,
          username: telegramUser.username || null,
          isVerified: true,
          verificationCode: null,
          verificationCodeExpires: null,
          lastLogin: new Date()
        });
        
        // Создаем лог о регистрации
        await storage.createLog({
          userId: user.id,
          action: 'user_registered',
          details: { phoneNumber },
          ipAddress: req.ip
        });
        
        // Пользователю нужно установить пароль
        return res.json({
          success: true,
          requirePassword: true,
          isNewUser: true,
          phoneNumber
        });
      }
    } catch (error) {
      console.error('Phone code verification error:', error);
      res.status(500).json({ 
        success: false,
        message: error instanceof Error ? error.message : 'Ошибка проверки кода' 
      });
    }
  });
  
  // 3. Установка пароля после регистрации
  app.post('/api/auth/phone/set-password', async (req, res) => {
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
  
  // 4. Вход по телефону и паролю
  app.post('/api/auth/phone/login', async (req, res) => {
    try {
      const { phoneNumber, password } = phoneLoginSchema.parse(req.body);
      
      // Получаем пользователя по телефону
      const user = await storage.getUserByPhoneNumber(phoneNumber);
      
      if (!user) {
        return res.status(404).json({ message: 'Пользователь не найден' });
      }
      
      if (!user.password) {
        return res.status(400).json({ message: 'Необходимо установить пароль' });
      }
      
      // Проверяем пароль
      const passwordValid = await comparePasswords(password, user.password);
      
      if (!passwordValid) {
        // Создаем лог о неудачной попытке входа
        await storage.createLog({
          userId: user.id,
          action: 'login_failed',
          details: { phoneNumber, reason: 'invalid_password' },
          ipAddress: req.ip
        });
        
        return res.status(400).json({ message: 'Неверный пароль' });
      }
      
      // Обновляем данные о последнем входе
      await storage.updateUser(user.id, {
        lastLogin: new Date()
      });
      
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
        
        // Создаем лог о входе
        storage.createLog({
          userId: user.id,
          action: 'user_login',
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
      console.error('Phone login error:', error);
      res.status(500).json({ message: 'Ошибка входа в систему' });
    }
  });

  // 4. Получение данных пользователя
  app.get('/api/user', isAuthenticated, async (req, res) => {
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

  // 5. Получение чатов пользователя
  app.get('/api/chats', isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      
      // Получаем чаты из базы данных
      let chats = await storage.listUserChats(user.id);
      let needsUpdate = false;
      
      // Если чатов нет или их меньше 5, пытаемся получить обновленные данные
      if (chats.length < 5) {
        try {
          // Получаем чаты через MTProto API
          const { getUserDialogs } = require('./telegram-auth');
          const dialogsResult = await getUserDialogs(5);
          
          if (dialogsResult.success) {
            console.log(`Retrieved ${dialogsResult.dialogs.length} dialogs from Telegram API`);
            
            // Обрабатываем данные диалогов и сохраняем в базу
            const savedChats = [];
            
            for (const dialog of dialogsResult.dialogs) {
              // Получаем информацию о чате/пользователе
              let chatInfo = null;
              let chatId = '';
              let chatType = '';
              let chatTitle = '';
              let chatPhoto = '';
              
              // Определяем тип диалога (личный чат, группа, канал)
              if (dialog.peer._ === 'peerUser') {
                // Находим пользователя по ID
                const userId = dialog.peer.user_id;
                const userObj = dialogsResult.users.find((u: any) => u.id === userId);
                
                if (userObj) {
                  chatId = `user_${userId}`;
                  chatType = 'private';
                  chatTitle = `${userObj.first_name || ''} ${userObj.last_name || ''}`.trim();
                  chatPhoto = userObj.photo ? `user_${userId}_photo` : ''; // Заглушка, позже можно добавить загрузку фото
                }
              } else if (dialog.peer._ === 'peerChat') {
                // Находим групповой чат по ID
                const chatPeerId = dialog.peer.chat_id;
                const chatObj = dialogsResult.chats.find((c: any) => c.id === chatPeerId);
                
                if (chatObj) {
                  chatId = `chat_${chatPeerId}`;
                  chatType = 'group';
                  chatTitle = chatObj.title || '';
                  chatPhoto = chatObj.photo ? `chat_${chatPeerId}_photo` : '';
                }
              } else if (dialog.peer._ === 'peerChannel') {
                // Находим канал по ID
                const channelId = dialog.peer.channel_id;
                const channelObj = dialogsResult.chats.find((c: any) => c.id === channelId);
                
                if (channelObj) {
                  chatId = `channel_${channelId}`;
                  chatType = 'channel';
                  chatTitle = channelObj.title || '';
                  chatPhoto = channelObj.photo ? `channel_${channelId}_photo` : '';
                }
              }
              
              // Находим последнее сообщение
              let lastMessage = null;
              if (dialog.top_message) {
                const message = dialogsResult.messages.find((m: any) => m.id === dialog.top_message);
                if (message) {
                  lastMessage = {
                    id: message.id,
                    text: message.message || '',
                    date: new Date(message.date * 1000)
                  };
                }
              }
              
              // Создаем или обновляем чат в базе данных
              if (chatId && chatTitle) {
                // Проверяем, существует ли уже этот чат в базе
                let existingChat = await storage.getChatByIds(user.id, chatId);
                
                if (existingChat) {
                  // Обновляем существующий чат
                  existingChat = await storage.updateChat(existingChat.id, {
                    title: chatTitle,
                    lastMessageDate: lastMessage ? lastMessage.date : existingChat.lastMessageDate,
                    lastMessageText: lastMessage ? lastMessage.text : existingChat.lastMessageText,
                    photoUrl: chatPhoto || existingChat.photoUrl
                  });
                  savedChats.push(existingChat);
                } else {
                  // Создаем новый чат
                  const newChat = await storage.createChat({
                    userId: user.id,
                    chatId: chatId,
                    type: chatType,
                    title: chatTitle,
                    lastMessageDate: lastMessage ? lastMessage.date : new Date(),
                    lastMessageText: lastMessage ? lastMessage.text : '',
                    unreadCount: dialog.unread_count || 0,
                    photoUrl: chatPhoto
                  });
                  savedChats.push(newChat);
                }
              }
            }
            
            // Обновляем список чатов
            chats = await storage.listUserChats(user.id);
            needsUpdate = true;
          } else {
            console.error('Error from Telegram API:', dialogsResult.error);
          }
        } catch (error) {
          console.error('Error fetching chats from Telegram:', error);
          // Продолжаем выполнение и возвращаем имеющиеся чаты
        }
      }
      
      // Создаем лог о запросе чатов
      await storage.createLog({
        userId: user.id,
        action: 'fetch_chats',
        details: { count: chats.length, updated: needsUpdate },
        ipAddress: req.ip
      });
      
      res.json(chats);
    } catch (error) {
      console.error('Error fetching chats:', error);
      res.status(500).json({ message: 'Ошибка получения чатов' });
    }
  });

  // 6. Получение сообщений из конкретного чата
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
          const { getChatHistory } = require('./telegram-auth');
          
          // Формируем правильный peer объект на основе структуры chatId
          let peer = null;
          
          // Разбираем chatId на части (формат: тип_id)
          const chatIdParts = chat.chatId.split('_');
          if (chatIdParts.length === 2) {
            const chatType = chatIdParts[0];
            const id = parseInt(chatIdParts[1]);
            
            if (!isNaN(id)) {
              if (chatType === 'user') {
                peer = { _: 'inputPeerUser', user_id: id, access_hash: 0 };
              } else if (chatType === 'chat') {
                peer = { _: 'inputPeerChat', chat_id: id };
              } else if (chatType === 'channel') {
                peer = { _: 'inputPeerChannel', channel_id: id, access_hash: 0 };
              }
            }
          }
          
          if (peer) {
            const historyResult = await getChatHistory(peer, limit);
            
            if (historyResult.success) {
              console.log(`Retrieved ${historyResult.messages.length} messages from Telegram API`);
              
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
                      senderId = `user_${userId}`;
                    }
                  }
                  
                  // Создаем сообщение в базе данных
                  const messageDate = new Date(msg.date * 1000);
                  
                  // Проверяем, существует ли сообщение с таким telegramId
                  const telegramMsgId = `${chat.chatId}_${msg.id}`;
                  const existingMessage = await storage.getMessageByTelegramId(telegramMsgId);
                  
                  if (!existingMessage) {
                    const newMessage = await storage.createMessage({
                      chatId: chat.id,
                      telegramId: telegramMsgId,
                      senderId: senderId,
                      senderName: senderName,
                      text: msg.message,
                      sentAt: messageDate,
                      isOutgoing: msg.out || false,
                      mediaType: msg.media ? msg.media._ : null,
                      mediaUrl: null // Пока не загружаем медиа
                    });
                    
                    savedMessages.push(newMessage);
                  }
                }
              }
              
              if (savedMessages.length > 0) {
                // Обновляем последнее сообщение в чате
                if (savedMessages.length > 0) {
                  const latestMessage = savedMessages.reduce((latest, msg) => 
                    new Date(msg.sentAt) > new Date(latest.sentAt) ? msg : latest, 
                    savedMessages[0]
                  );
                  
                  await storage.updateChat(chat.id, {
                    lastMessageDate: latestMessage.sentAt,
                    lastMessageText: latestMessage.text
                  });
                }
                
                // Обновляем список сообщений
                messages = await storage.listChatMessages(chat.id);
                needsUpdate = true;
              }
            } else {
              console.error('Error from Telegram API:', historyResult.error);
            }
          } else {
            console.error('Could not parse chatId or create peer object');
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

  // 7. Выход из системы
  app.post('/api/auth/logout', isAuthenticated, async (req, res) => {
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

  // === АДМИН API ===
  
  // 1. Получение списка пользователей
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

  // 2. Получение статистики для админ-панели
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
  
  // 3. Получение логов системы
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

  // 4. Блокировка/разблокировка пользователя
  app.post('/api/admin/users/:id/toggle-block', isAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: 'Пользователь не найден' });
      }
      
      // Инвертируем статус активности
      const updatedUser = await storage.updateUser(userId, {
        isActive: !user.isActive
      });
      
      // Создаем лог о действии
      const adminUser = req.user as any;
      await storage.createLog({
        userId: adminUser.id,
        action: user.isActive ? 'user_blocked' : 'user_unblocked',
        details: { targetUserId: userId },
        ipAddress: req.ip
      });
      
      res.json(updatedUser);
    } catch (error) {
      console.error('Admin toggle block error:', error);
      res.status(500).json({ message: 'Ошибка изменения статуса пользователя' });
    }
  });

  // 5. Получение сессий пользователя
  app.get('/api/admin/users/:id/sessions', isAdmin, async (req, res) => {
    try {
      const userId = parseInt(req.params.id);
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: 'Пользователь не найден' });
      }
      
      const sessions = await storage.listUserSessions(userId);
      
      res.json(sessions);
    } catch (error) {
      console.error('Admin sessions fetch error:', error);
      res.status(500).json({ message: 'Ошибка получения сессий' });
    }
  });
  
  // 6. Получение списка всех сессий
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
  
  // 7. Завершение сессии
  app.post('/api/admin/sessions/:token/terminate', isAdmin, async (req, res) => {
    try {
      const { token } = req.params;
      
      await storage.deleteSession(token);
      
      // Создаем лог о завершении сессии
      const adminUser = (req as any).adminUser || req.user as any;
      
      if (adminUser) {
        await storage.createLog({
          userId: adminUser.id,
          action: 'session_terminated',
          details: { sessionToken: token },
          ipAddress: req.ip
        });
      }
      
      res.json({ success: true });
    } catch (error) {
      console.error('Admin terminate session error:', error);
      res.status(500).json({ message: 'Ошибка завершения сессии' });
    }
  });
  
  // 8. Получение всех чатов для админа
  app.get('/api/admin/chats', isAdmin, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 20;
      const offset = parseInt(req.query.offset as string) || 0;
      
      // Получаем все чаты и их пользователей
      const allChats = await storage.listAllChats(limit, offset);
      const totalChats = await storage.countChats();
      
      // Для каждого чата добавляем информацию о количестве сообщений
      const enrichedChats = await Promise.all(
        allChats.map(async (chat) => {
          // Получаем сообщения для подсчета их количества
          const chatMessages = await storage.listChatMessages(chat.id, 1000);
          
          return {
            ...chat,
            messagesCount: chatMessages.length
          };
        })
      );
      
      res.json({
        chats: enrichedChats,
        pagination: {
          total: totalChats,
          limit,
          offset
        }
      });
    } catch (error) {
      console.error('Admin chats fetch error:', error);
      res.status(500).json({ message: 'Ошибка получения чатов' });
    }
  });
  
  // 9. Получение сообщений чата для админа
  app.get('/api/admin/chats/:id/messages', isAdmin, async (req, res) => {
    try {
      const chatId = parseInt(req.params.id);
      const limit = parseInt(req.query.limit as string) || 50;
      
      const messagesData = await storage.listChatMessages(chatId, limit);
      
      res.json(messagesData);
    } catch (error) {
      console.error('Admin chat messages fetch error:', error);
      res.status(500).json({ message: 'Ошибка получения сообщений чата' });
    }
  });

  // 6. Авторизация администратора по логину и паролю
  app.post('/api/admin/login', async (req, res) => {
    try {
      const { username, password } = req.body;
      
      if (!username || !password) {
        return res.status(400).json({ message: 'Отсутствуют обязательные параметры' });
      }

      // Проверка пользователя admin в базе
      const user = await storage.getUserByUsername(username);
      
      if (!user) {
        // Создаем админа при первом входе, если его нет
        if (username === 'admin' && password === 'admin') {
          const newAdmin = await storage.createUser({
            telegramId: 'admin',
            username: 'admin',
            firstName: 'Administrator',
            password: 'admin',
            isAdmin: true,
            lastLogin: new Date()
          });
          
          // Создаем сессию для администратора
          const sessionToken = randomBytes(32).toString('hex');
          const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 1 неделя
          
          await storage.createSession({
            userId: newAdmin.id,
            sessionToken,
            ipAddress: req.ip || null,
            userAgent: req.headers['user-agent'] || null,
            expiresAt
          });
          
          await storage.createLog({
            userId: newAdmin.id,
            action: 'admin_created',
            details: { username },
            ipAddress: req.ip
          });
          
          return res.json({
            success: true,
            user: {
              id: newAdmin.id,
              username: newAdmin.username,
              isAdmin: newAdmin.isAdmin
            },
            sessionToken
          });
        }
        
        return res.status(401).json({ message: 'Неверное имя пользователя или пароль' });
      }
      
      // Проверка пароля
      if (user.password !== password) {
        return res.status(401).json({ message: 'Неверное имя пользователя или пароль' });
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
      
      await storage.createLog({
        userId: user.id,
        action: 'admin_login',
        details: { username },
        ipAddress: req.ip
      });
      
      res.json({
        success: true,
        user: {
          id: user.id,
          username: user.username,
          isAdmin: user.isAdmin
        },
        sessionToken
      });
    } catch (error) {
      console.error('Admin login error:', error);
      res.status(500).json({ message: 'Ошибка авторизации' });
    }
  });

  // 7. Изменение пароля администратора
  app.post('/api/admin/change-password', isAdmin, async (req, res) => {
    try {
      const { currentPassword, newPassword } = req.body;
      const user = req.user as any;
      
      if (!currentPassword || !newPassword) {
        return res.status(400).json({ message: 'Отсутствуют обязательные параметры' });
      }
      
      // Получаем актуальные данные пользователя
      const dbUser = await storage.getUser(user.id);
      
      if (!dbUser) {
        return res.status(404).json({ message: 'Пользователь не найден' });
      }
      
      // Проверяем текущий пароль
      if (dbUser.password !== currentPassword) {
        return res.status(401).json({ message: 'Неверный текущий пароль' });
      }
      
      // Обновляем пароль
      await storage.updateUserPassword(user.id, newPassword);
      
      await storage.createLog({
        userId: user.id,
        action: 'admin_password_change',
        details: { },
        ipAddress: req.ip
      });
      
      res.json({ success: true });
    } catch (error) {
      console.error('Change password error:', error);
      res.status(500).json({ message: 'Ошибка изменения пароля' });
    }
  });

  // 8. Получение настроек системы
  app.get('/api/admin/settings', isAdmin, async (req, res) => {
    try {
      const settingsList = await storage.listSettings();
      res.json(settingsList);
    } catch (error) {
      console.error('Settings fetch error:', error);
      res.status(500).json({ message: 'Ошибка получения настроек' });
    }
  });

  // 9. Обновление настройки
  app.post('/api/admin/settings', isAdmin, async (req, res) => {
    try {
      const { key, value, description } = req.body;
      
      if (!key || value === undefined) {
        return res.status(400).json({ message: 'Отсутствуют обязательные параметры' });
      }
      
      // Если обновляется токен Telegram-бота, используем специальную функцию
      if (key === 'telegram_bot_token') {
        const { updateBotToken } = await import('./telegram');
        const success = await updateBotToken(value);
        
        if (!success) {
          return res.status(400).json({ message: 'Ошибка обновления токена бота' });
        }
        
        // Используем userId из токена администратора или дефолтное значение 1
        const userId = req.user ? (req.user as any).id : 1;
        
        // Создаем лог об обновлении токена
        await storage.createLog({
          userId: userId,
          action: 'bot_token_updated',
          details: { success },
          ipAddress: req.ip
        });
        
        return res.json({ key, value: '***HIDDEN***', description });
      }
      
      // Для всех остальных настроек используем обычный метод
      const setting = await storage.upsertSetting(key, value, description);
      
      // Используем userId из токена администратора или дефолтное значение 1
      const userId = req.user ? (req.user as any).id : 1;
      
      await storage.createLog({
        userId: userId,
        action: 'setting_update',
        details: { key, value },
        ipAddress: req.ip
      });
      
      res.json(setting);
    } catch (error) {
      console.error('Setting update error:', error);
      res.status(500).json({ message: 'Ошибка обновления настройки' });
    }
  });
  
  // 10. Отправка тестового уведомления администратору
  app.post('/api/admin/send-test-notification', isAdmin, async (req, res) => {
    try {
      // Получаем настройки уведомлений
      const notificationsEnabled = await storage.getSettingValue("notifications_enabled");
      const adminChatId = await storage.getSettingValue("admin_chat_id");
      
      // Проверяем наличие необходимых настроек
      if (notificationsEnabled !== "true") {
        return res.status(400).json({ message: 'Уведомления отключены в настройках' });
      }
      
      if (!adminChatId) {
        return res.status(400).json({ message: 'Не указан ID чата администратора' });
      }
      
      // Импортируем функцию для отправки тестового уведомления
      const { sendTestNotification } = await import('./telegram');
      
      // Отправляем тестовое уведомление
      const success = await sendTestNotification(adminChatId);
      
      if (success) {
        // Используем userId из токена администратора или дефолтное значение 1
        const userId = req.user ? (req.user as any).id : 1;
        
        // Создаем лог об отправке тестового уведомления
        await storage.createLog({
          userId: userId,
          action: 'test_notification_sent',
          details: { adminChatId },
          ipAddress: req.ip
        });
        
        res.json({ success: true, message: 'Тестовое уведомление отправлено' });
      } else {
        throw new Error('Не удалось отправить тестовое уведомление');
      }
    } catch (error) {
      console.error('Admin test notification error:', error);
      res.status(500).json({ message: 'Ошибка отправки тестового уведомления' });
    }
  });
  
  // === МАРШРУТЫ ДЛЯ АВТОРИЗАЦИИ ЧЕРЕЗ QR КОД ===
  
  // 1. Создание QR кода для входа
  app.post('/api/auth/qr/create', async (req, res) => {
    try {
      // Генерируем QR код через Telegram API
      const result = await createQRLoginCode();
      
      if (!result.success) {
        return res.status(500).json({ 
          success: false,
          message: result.error || 'Не удалось создать QR код' 
        });
      }
      
      // Создаем лог о создании QR кода
      await storage.createLog({
        userId: null,
        action: 'qr_code_created',
        details: { token: result.token },
        ipAddress: req.ip
      });
      
      return res.status(200).json({
        success: true,
        token: result.token,
        url: result.url,
        expires: result.expires
      });
    } catch (error: any) {
      console.error('Error creating QR code:', error);
      res.status(500).json({ 
        success: false,
        message: error.message || 'Ошибка создания QR кода' 
      });
    }
  });
  
  // 2. Проверка статуса авторизации по QR коду
  app.post('/api/auth/qr/check', async (req, res) => {
    try {
      const { token } = qrTokenSchema.parse(req.body);
      
      // Проверяем статус QR-авторизации
      const result = await checkQRLoginStatus(token);
      
      if (result.success && result.user) {
        // Пользователь успешно авторизовался через QR код
        
        // Проверяем, существует ли уже пользователь с таким Telegram ID
        let user = await storage.getUserByTelegramId(result.user.id);
        
        if (!user) {
          // Создаем нового пользователя
          user = await storage.createUser({
            telegramId: result.user.id,
            username: result.user.username || `user_${result.user.id}`,
            firstName: result.user.firstName || '',
            lastName: result.user.lastName || '',
            phoneNumber: result.user.phone || '',
            isActive: true,
            role: 'user',
            createdAt: new Date()
          });
          
          // Создаем лог о регистрации пользователя
          await storage.createLog({
            userId: user.id,
            action: 'user_registered_qr',
            details: { telegramId: result.user.id },
            ipAddress: req.ip
          });
        }
        
        // Создаем сессию для пользователя
        const sessionToken = randomBytes(48).toString('hex');
        const session = await storage.createSession({
          userId: user.id,
          token: sessionToken,
          ipAddress: req.ip || null,
          userAgent: req.headers['user-agent'] || null,
          expiresAt: new Date(Date.now() + (30 * 24 * 60 * 60 * 1000)) // 30 дней
        });
        
        // Авторизуем пользователя
        req.login(user, (err) => {
          if (err) {
            return res.status(500).json({ message: 'Ошибка авторизации' });
          }
          
          // Создаем лог о входе пользователя
          storage.createLog({
            userId: user.id,
            action: 'user_login_qr',
            details: { telegramId: result.user.id },
            ipAddress: req.ip
          });
          
          // Отправляем информацию о пользователе
          return res.status(200).json({
            success: true,
            user: {
              id: user.id,
              username: user.username,
              firstName: user.firstName,
              lastName: user.lastName,
              role: user.role,
              isAdmin: user.isAdmin
            },
            sessionToken
          });
        });
      } else {
        // Если пользователь еще не авторизовался, возвращаем статус ожидания
        return res.status(200).json({
          success: false,
          waiting: result.error === 'Waiting for QR code scan',
          message: result.error || 'Ожидание сканирования QR кода'
        });
      }
    } catch (error: any) {
      console.error('Error checking QR login:', error);
      res.status(500).json({ 
        success: false,
        message: error.message || 'Ошибка проверки QR авторизации' 
      });
    }
  });

  // Создание HTTP сервера
  const httpServer = createServer(app);

  return httpServer;
}
