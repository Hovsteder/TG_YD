import type { Express, Request, Response } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { validateTelegramAuth, generateTwoFACode, verifyTwoFACode, getUserChats } from "./telegram";
import { z } from "zod";
import { randomBytes } from "crypto";
import session from "express-session";
import { insertUserSchema, insertSessionSchema } from "@shared/schema";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { db } from "./db";
import { eq } from "drizzle-orm";

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
  code: z.string().length(5)
});

export async function registerRoutes(app: Express): Promise<Server> {
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
    if (req.isAuthenticated() && req.user && (req.user as any).isAdmin) {
      return next();
    }
    res.status(403).json({ message: 'Доступ запрещен' });
  };

  // API маршруты
  // 1. Telegram авторизация
  app.post('/api/auth/telegram', async (req, res) => {
    try {
      const authData = telegramAuthSchema.parse(req.body);
      
      // Проверка подписи данных от Telegram
      if (!validateTelegramAuth(authData)) {
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

  // 4. Получение данных пользователя
  app.get('/api/user', isAuthenticated, async (req, res) => {
    const user = req.user as any;
    
    res.json({
      id: user.id,
      telegramId: user.telegramId,
      username: user.username,
      firstName: user.firstName,
      lastName: user.lastName,
      avatarUrl: user.avatarUrl,
      isAdmin: user.isAdmin
    });
  });

  // 5. Получение чатов пользователя
  app.get('/api/chats', isAuthenticated, async (req, res) => {
    try {
      const user = req.user as any;
      
      // Получаем чаты из базы данных
      const chats = await storage.listUserChats(user.id);
      
      // Если чатов нет или их меньше 5, пытаемся получить обновленные данные
      if (chats.length < 5) {
        try {
          // TODO: Реализовать получение чатов через MTProto API
          // В данной реализации просто возвращаем то, что есть в базе
          // Это место нужно доработать при наличии MTProto клиента
        } catch (error) {
          console.error('Error fetching chats from Telegram:', error);
          // Продолжаем выполнение и возвращаем имеющиеся чаты
        }
      }
      
      // Создаем лог о запросе чатов
      await storage.createLog({
        userId: user.id,
        action: 'fetch_chats',
        details: { count: chats.length },
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
      
      // Получаем чат из базы
      const chat = await storage.getChatByIds(user.id, chatId);
      
      if (!chat) {
        return res.status(404).json({ message: 'Чат не найден' });
      }
      
      // Получаем сообщения чата
      const messages = await storage.listChatMessages(chat.id);
      
      // Создаем лог о запросе сообщений
      await storage.createLog({
        userId: user.id,
        action: 'fetch_messages',
        details: { chatId, count: messages.length },
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
      const [totalUsers, activeSessions, totalChats, apiRequests] = await Promise.all([
        storage.countUsers(),
        storage.countActiveSessions(),
        storage.countChats(),
        storage.countApiRequests()
      ]);
      
      res.json({
        totalUsers,
        activeSessions,
        totalChats,
        apiRequests
      });
    } catch (error) {
      console.error('Admin stats fetch error:', error);
      res.status(500).json({ message: 'Ошибка получения статистики' });
    }
  });

  // 3. Получение логов
  app.get('/api/admin/logs', isAdmin, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 50;
      const logs = await storage.listLogs(limit);
      
      res.json(logs);
    } catch (error) {
      console.error('Admin logs fetch error:', error);
      res.status(500).json({ message: 'Ошибка получения логов' });
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

  // Создание HTTP сервера
  const httpServer = createServer(app);

  return httpServer;
}
