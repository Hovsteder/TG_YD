import { 
  users, sessions, chats, messages, logs, settings,
  type User, type InsertUser,
  type Session, type InsertSession,
  type Chat, type InsertChat,
  type Message, type InsertMessage,
  type Log, type InsertLog,
  type Setting, type InsertSetting,
  qrSessions, type QrSession, type InsertQrSession
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and, sql, inArray, gt, lt } from "drizzle-orm";

export interface IStorage {
  // Пользователи
  getUser(id: number): Promise<User | undefined>;
  getUserById(id: number): Promise<User | undefined>;
  getUserByTelegramId(telegramId: string): Promise<User | undefined>;
  getUserBySessionToken(sessionToken: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  getUserByPhoneNumber(phoneNumber: string): Promise<User | undefined>;
  getUserByEmail(email: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUser(id: number, data: Partial<InsertUser>): Promise<User | undefined>;
  updateUserPassword(id: number, password: string): Promise<User | undefined>;
  listUsers(limit?: number, offset?: number): Promise<User[]>;
  countUsers(): Promise<number>;
  listAdmins(): Promise<User[]>;
  
  // Сессии
  createSession(session: InsertSession): Promise<Session>;
  getSession(token: string): Promise<Session | undefined>;
  deleteSession(token: string): Promise<void>;
  listUserSessions(userId: number): Promise<Session[]>;
  listAllSessions(limit?: number, offset?: number): Promise<Session[]>;
  countActiveSessions(): Promise<number>;
  
  // QR Сессии
  createQrSession(session: InsertQrSession): Promise<QrSession>;
  getQrSessionBySessionToken(sessionToken: string): Promise<QrSession | undefined>;
  getQrSessionByTelegramToken(telegramToken: string): Promise<QrSession | undefined>;
  updateQrSessionUserId(sessionToken: string, userId: number): Promise<QrSession | undefined>;
  updateQrSessionUser(sessionToken: string, userId: string, userData: any): Promise<boolean>;
  deleteQrSession(sessionToken: string): Promise<void>;
  deleteExpiredQrSessions(): Promise<void>;
  
  // Чаты
  createChat(chat: InsertChat): Promise<Chat>;
  getChatByIds(userId: number, chatId: string): Promise<Chat | undefined>;
  getChatById(id: number): Promise<Chat | undefined>;
  updateChat(id: number, data: Partial<InsertChat>): Promise<Chat | undefined>;
  getUserChats(userId: number): Promise<Chat[]>;
  listUserChats(userId: number, limit?: number, type?: string): Promise<Chat[]>;
  listAllChats(limit?: number, offset?: number): Promise<Chat[]>;
  countChats(): Promise<number>;
  
  // Сообщения
  createMessage(message: InsertMessage): Promise<Message>;
  getMessageByTelegramId(telegramId: string): Promise<Message | undefined>;
  getMessageByTelegramIdAndChatId(telegramId: string, chatId: number): Promise<Message | undefined>;
  listChatMessages(chatId: number, limit?: number): Promise<Message[]>;
  clearChatMessages(chatId: number): Promise<void>;
  deleteOldMessages(chatId: number, keepLastCount?: number): Promise<void>;
  createOrUpdateMessage(message: any): Promise<Message>;
  
  // Логи
  createLog(log: InsertLog): Promise<Log>;
  listLogs(limit?: number): Promise<Log[]>;
  listLogsByAction(action: string, fromDate?: Date | number): Promise<Log[]>;
  countApiRequests(): Promise<number>;
  
  // Настройки
  getSetting(key: string): Promise<Setting | undefined>;
  getSettingValue(key: string): Promise<string | undefined>;
  upsertSetting(key: string, value: string, description?: string): Promise<Setting>;
  listSettings(): Promise<Setting[]>;
}

export class DatabaseStorage implements IStorage {
  // Пользователи
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
  }

  async getUserById(id: number): Promise<User | undefined> {
    return this.getUser(id);
  }

  async getUserByTelegramId(telegramId: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.telegramId, telegramId));
    return user;
  }

  async getUserBySessionToken(sessionToken: string): Promise<User | undefined> {
    const [result] = await db
      .select({ user: users })
      .from(sessions)
      .innerJoin(users, eq(sessions.userId, users.id))
      .where(eq(sessions.sessionToken, sessionToken));
    
    return result?.user;
  }

  async createUser(user: InsertUser): Promise<User> {
    const [newUser] = await db.insert(users).values(user).returning();
    return newUser;
  }

  async updateUser(id: number, data: Partial<InsertUser>): Promise<User | undefined> {
    const [updatedUser] = await db
      .update(users)
      .set({ ...data, lastLogin: data.lastLogin || new Date() })
      .where(eq(users.id, id))
      .returning();
    
    return updatedUser;
  }

  async listUsers(limit = 20, offset = 0): Promise<User[]> {
    return db
      .select()
      .from(users)
      .orderBy(desc(users.createdAt))
      .limit(limit)
      .offset(offset);
  }

  async countUsers(): Promise<number> {
    const [result] = await db
      .select({ count: sql<number>`count(*)` })
      .from(users);
    
    return result?.count || 0;
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.username, username));
    
    return user;
  }

  async updateUserPassword(id: number, password: string): Promise<User | undefined> {
    const [updatedUser] = await db
      .update(users)
      .set({ password })
      .where(eq(users.id, id))
      .returning();
    
    return updatedUser;
  }

  async listAdmins(): Promise<User[]> {
    return db
      .select()
      .from(users)
      .where(eq(users.isAdmin, true));
  }
  
  async getUserByPhoneNumber(phoneNumber: string): Promise<User | undefined> {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.phoneNumber, phoneNumber));
    
    return user;
  }
  
  async getUserByEmail(email: string): Promise<User | undefined> {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email));
    
    return user;
  }

  // Сессии
  async createSession(session: InsertSession): Promise<Session> {
    const [newSession] = await db.insert(sessions).values(session).returning();
    return newSession;
  }

  async getSession(token: string): Promise<Session | undefined> {
    const [session] = await db
      .select()
      .from(sessions)
      .where(eq(sessions.sessionToken, token));
    
    return session;
  }

  async deleteSession(token: string): Promise<void> {
    await db
      .delete(sessions)
      .where(eq(sessions.sessionToken, token));
  }

  async listUserSessions(userId: number): Promise<Session[]> {
    return db
      .select()
      .from(sessions)
      .where(eq(sessions.userId, userId))
      .orderBy(desc(sessions.createdAt));
  }

  async listAllSessions(limit = 20, offset = 0): Promise<Session[]> {
    const sessionsData = await db
      .select()
      .from(sessions)
      .leftJoin(users, eq(sessions.userId, users.id))
      .orderBy(desc(sessions.createdAt))
      .limit(limit)
      .offset(offset);
    
    // Преобразуем результат к нужному формату
    return sessionsData.map(result => ({
      ...result.sessions,
      user: result.users
    }));
  }
  
  async countActiveSessions(): Promise<number> {
    const now = new Date();
    const [result] = await db
      .select({ count: sql<number>`count(*)` })
      .from(sessions)
      .where(sql`${sessions.expiresAt} > ${now}`);
    
    return result?.count || 0;
  }

  // QR Сессии
  async createQrSession(session: InsertQrSession): Promise<QrSession> {
    console.log("Создание новой QR сессии:", JSON.stringify(session, null, 2));
    try {
      // Перед созданием новой сессии, удалим старую с таким же sessionToken, если она существует
      await this.deleteQrSession(session.sessionToken);
      const [newQrSession] = await db.insert(qrSessions).values(session).returning();
      console.log("QR сессия успешно создана:", newQrSession.id);
      return newQrSession;
    } catch (error) {
      console.error("Ошибка при создании QR сессии:", error);
      throw error;
    }
  }

  async getQrSessionBySessionToken(sessionToken: string): Promise<QrSession | undefined> {
    const [qrSession] = await db
      .select()
      .from(qrSessions)
      .where(eq(qrSessions.sessionToken, sessionToken));
    
    return qrSession;
  }

  async getQrSessionByTelegramToken(telegramToken: string): Promise<QrSession | undefined> {
    const [qrSession] = await db
      .select()
      .from(qrSessions)
      .where(eq(qrSessions.telegramToken, telegramToken));
    
    return qrSession;
  }

  async updateQrSessionUserId(sessionToken: string, userId: number): Promise<QrSession | undefined> {
    const [updatedSession] = await db
      .update(qrSessions)
      .set({ userId })
      .where(eq(qrSessions.sessionToken, sessionToken))
      .returning();
    
    return updatedSession;
  }

  async updateQrSessionUser(sessionToken: string, userId: string, userData: any): Promise<boolean> {
    try {
      // Обновляем сессию, добавляя userId (преобразуем в число) и userData (JSON)
      const userIdInt = parseInt(userId, 10);
      if (isNaN(userIdInt)) {
          console.error(`Invalid userId provided to updateQrSessionUser: ${userId}`);
          return false;
      }
      const result = await db
        .update(qrSessions)
        .set({ 
            userId: userIdInt, 
            userData: userData // Drizzle автоматически обработает JSON
        })
        .where(eq(qrSessions.sessionToken, sessionToken));
      console.log(`[Storage] Updated QR session ${sessionToken} with userId ${userIdInt}. Rows affected: ${result.rowCount}`);
      return result.rowCount > 0;
    } catch (error) {
      console.error("Error updating QR session user:", error);
      return false;
    }
  }

  async deleteQrSession(sessionToken: string): Promise<void> {
    await db
      .delete(qrSessions)
      .where(eq(qrSessions.sessionToken, sessionToken));
  }
  
  async deleteExpiredQrSessions(): Promise<void> {
     const now = new Date();
     await db
      .delete(qrSessions)
      .where(sql`${qrSessions.expiresAt} <= ${now}`);
  }

  // Чаты
  async createChat(chat: InsertChat): Promise<Chat> {
    console.log("Создание нового чата:", JSON.stringify(chat, null, 2));
    try {
      // Проверяем корректность полей
      const validChat = { ...chat };
      
      // Конвертируем даты в корректный формат, если нужно
      if (chat.lastMessageDate && !(chat.lastMessageDate instanceof Date)) {
        try {
          validChat.lastMessageDate = new Date(chat.lastMessageDate);
          console.log("Преобразована дата сообщения:", validChat.lastMessageDate);
        } catch (e) {
          console.warn("Ошибка при преобразовании даты:", e);
          validChat.lastMessageDate = new Date();
        }
      }
      
      const [newChat] = await db.insert(chats).values(validChat).returning();
      console.log("Чат успешно создан:", newChat.id);
      return newChat;
    } catch (error) {
      console.error("Ошибка при создании чата:", error);
      throw error;
    }
  }

  async getChatByIds(userId: number, chatId: string): Promise<Chat | undefined> {
    const [chat] = await db
      .select()
      .from(chats)
      .where(and(
        eq(chats.userId, userId),
        eq(chats.chatId, chatId)
      ));
    
    return chat;
  }
  
  async getChatById(id: number): Promise<Chat | undefined> {
    const [chat] = await db
      .select()
      .from(chats)
      .where(eq(chats.id, id));
    
    return chat;
  }

  async updateChat(id: number, data: Partial<InsertChat>): Promise<Chat | undefined> {
    console.log(`Updating chat [ID: ${id}], data:`, data);
    
    // Конвертируем поля даты из строки в объект Date если необходимо
    const preparedData = { ...data };
    if (preparedData.lastMessageDate && typeof preparedData.lastMessageDate === 'string') {
      preparedData.lastMessageDate = new Date(preparedData.lastMessageDate);
    }
    
    const [updatedChat] = await db
      .update(chats)
      .set(preparedData)
      .where(eq(chats.id, id))
      .returning();
    
    return updatedChat;
  }

  async getUserChats(userId: number): Promise<Chat[]> {
    console.log(`Getting chats for user ID: ${userId}`);
    // Используем существующий метод listUserChats с большим лимитом для получения всех чатов
    return this.listUserChats(userId, 1000);
  }

  async listUserChats(userId: number, limit = 100, type?: string): Promise<Chat[]> {
    const query = db
      .select()
      .from(chats)
      .where(eq(chats.userId, userId));
    
    // Дополнительно фильтруем по типу, если передан
    if (type) {
      query.where(eq(chats.type, type));
    }
    
    return query
      .orderBy(desc(chats.lastUpdated))
      .limit(limit);
  }

  async listAllChats(limit = 20, offset = 0): Promise<Chat[]> {
    const chatsData = await db
      .select()
      .from(chats)
      .leftJoin(users, eq(chats.userId, users.id))
      .orderBy(desc(chats.lastUpdated))
      .limit(limit)
      .offset(offset);
    
    // Преобразуем результат к нужному формату
    return chatsData.map(result => ({
      ...result.chats,
      user: result.users
    }));
  }
  
  async countChats(): Promise<number> {
    const [result] = await db
      .select({ count: sql<number>`count(*)` })
      .from(chats);
    
    return result?.count || 0;
  }

  // Сообщения
  async createMessage(message: InsertMessage): Promise<Message> {
    const [newMessage] = await db.insert(messages).values(message).returning();
    return newMessage;
  }

  async getMessageByTelegramId(telegramId: string): Promise<Message | undefined> {
    const [message] = await db
      .select()
      .from(messages)
      .where(eq(messages.telegramId, telegramId));
    
    return message;
  }
  
  async getMessageByTelegramIdAndChatId(telegramId: string, chatId: number): Promise<Message | undefined> {
    const [message] = await db
      .select()
      .from(messages)
      .where(
        and(
          eq(messages.telegramMessageId, telegramId),
          eq(messages.chatId, chatId)
        )
      );
    
    return message;
  }
  
  async listChatMessages(chatId: number, limit = 100): Promise<Message[]> {
    console.log(`[Storage] Retrieving messages for chat ID: ${chatId} with limit: ${limit}`);
    try {
      const chatMessages = await db
        .select()
        .from(messages)
        .where(eq(messages.chatId, chatId))
        .orderBy(desc(messages.sentAt))
        .limit(limit);
      
      console.log(`[Storage] Found ${chatMessages.length} messages for chat ID: ${chatId}`);
      return chatMessages;
    } catch (error) {
      console.error(`[Storage] Error retrieving messages for chat ID: ${chatId}:`, error);
      return [];
    }
  }
  
  async clearChatMessages(chatId: number): Promise<void> {
    await db
      .delete(messages)
      .where(eq(messages.chatId, chatId));
  }
  
  async deleteOldMessages(chatId: number, keepLastCount = 20): Promise<void> {
    try {
      // Получаем ID последних сообщений, которые нужно сохранить
      const latestMessages = await db
        .select({ id: messages.id })
        .from(messages)
        .where(eq(messages.chatId, chatId))
        .orderBy(desc(messages.sentAt))
        .limit(keepLastCount);
      
      if (latestMessages.length === 0) return;
      
      // Получаем массив ID для сохраняемых сообщений
      const idsToKeep = latestMessages.map(m => m.id);
      
      if (idsToKeep.length > 0) {
        // Получаем сообщения, которые нужно удалить
        const messagesToDelete = await db
          .select({ id: messages.id })
          .from(messages)
          .where(
            and(
              eq(messages.chatId, chatId),
              // Используем NOT для проверки, что ID не входит в список сохраняемых
              sql`${messages.id} NOT IN (${idsToKeep.join(', ')})`
            )
          );
        
        // Если есть сообщения для удаления
        if (messagesToDelete.length > 0) {
          const idsToDelete = messagesToDelete.map(m => m.id);
          
          // Удаляем сообщения по списку ID
          await db
            .delete(messages)
            .where(
              and(
                eq(messages.chatId, chatId),
                inArray(messages.id, idsToDelete)
              )
            );
          
          console.log(`Deleted ${messagesToDelete.length} old messages from chat ID ${chatId}`);
        }
      }
    } catch (error) {
      console.error('Error deleting old messages:', error);
    }
  }

  // Создает новое сообщение или обновляет существующее
  async createOrUpdateMessage(message: any): Promise<Message> {
    try {
      // Проверяем, существует ли сообщение с таким messageId в этом чате
      const [existingMessage] = await db
        .select()
        .from(messages)
        .where(
          and(
            eq(messages.chatId, message.chatId),
            eq(messages.messageId, message.messageId)
          )
        );
      
      if (existingMessage) {
        // Обновляем существующее сообщение
        const [updatedMessage] = await db
          .update(messages)
          .set({
            text: message.text,
            metadata: message.metadata ? message.metadata : null,
            // Другие поля, которые могут быть обновлены
            sentAt: message.sentAt || existingMessage.sentAt || message.timestamp,
            isOutgoing: message.isOutgoing !== undefined ? message.isOutgoing : existingMessage.isOutgoing
          })
          .where(eq(messages.id, existingMessage.id))
          .returning();
        
        return updatedMessage;
      } else {
        // Создаем новое сообщение
        const [newMessage] = await db
          .insert(messages)
          .values({
            chatId: message.chatId,
            messageId: message.messageId,
            telegramId: message.telegramId,
            senderId: message.senderId || null,
            text: message.text || '',
            timestamp: message.timestamp || new Date(),
            sentAt: message.sentAt || message.timestamp || new Date(),
            isOutgoing: message.isOutgoing !== undefined ? message.isOutgoing : false,
            metadata: message.metadata || null,
          })
          .returning();
        
        return newMessage;
      }
    } catch (error) {
      console.error('Error in createOrUpdateMessage:', error);
      throw error;
    }
  }

  // Логи
  async createLog(log: InsertLog): Promise<Log> {
    const [newLog] = await db.insert(logs).values(log).returning();
    return newLog;
  }

  async listLogs(limit = 50): Promise<Log[]> {
    return db
      .select()
      .from(logs)
      .orderBy(desc(logs.timestamp))
      .limit(limit);
  }

  async listLogsByAction(action: string, fromDateParam?: Date | number): Promise<Log[]> {
    // Если fromDate передан как число, считаем что это последние N логов
    if (typeof fromDateParam === 'number') {
      return db
        .select()
        .from(logs)
        .where(eq(logs.action, action))
        .orderBy(desc(logs.timestamp))
        .limit(fromDateParam);
    }
    
    // Если передана дата, фильтруем по дате
    if (fromDateParam instanceof Date) {
      return db
        .select()
        .from(logs)
        .where(and(
          eq(logs.action, action),
          sql`${logs.timestamp} >= ${fromDateParam}`
        ))
        .orderBy(desc(logs.timestamp));
    }
    
    // По умолчанию просто возвращаем все логи заданного типа
    return db
      .select()
      .from(logs)
      .where(eq(logs.action, action))
      .orderBy(desc(logs.timestamp));
  }

  async countApiRequests(): Promise<number> {
    const [result] = await db
      .select({ count: sql<number>`count(*)` })
      .from(logs)
      .where(eq(logs.action, 'api_request'));
    
    return result?.count || 0;
  }

  // Настройки
  async getSetting(key: string): Promise<Setting | undefined> {
    const [setting] = await db
      .select()
      .from(settings)
      .where(eq(settings.key, key));
    
    return setting;
  }

  async getSettingValue(key: string): Promise<string | undefined> {
    const setting = await this.getSetting(key);
    return setting?.value || undefined;
  }

  async upsertSetting(key: string, value: string, description?: string): Promise<Setting> {
    const existingSetting = await this.getSetting(key);
    
    if (existingSetting) {
      const [updated] = await db
        .update(settings)
        .set({ 
          value, 
          description: description || existingSetting.description,
          updatedAt: new Date()
        })
        .where(eq(settings.key, key))
        .returning();
      
      return updated;
    } else {
      const [newSetting] = await db
        .insert(settings)
        .values({
          key,
          value,
          description
        })
        .returning();
      
      return newSetting;
    }
  }

  async listSettings(): Promise<Setting[]> {
    return db
      .select()
      .from(settings)
      .orderBy(settings.key);
  }
}

export const storage = new DatabaseStorage();
