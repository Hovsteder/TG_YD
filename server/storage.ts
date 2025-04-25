import { 
  users, sessions, chats, messages, logs,
  type User, type InsertUser,
  type Session, type InsertSession,
  type Chat, type InsertChat,
  type Message, type InsertMessage,
  type Log, type InsertLog
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and, sql, inArray } from "drizzle-orm";

export interface IStorage {
  // Пользователи
  getUser(id: number): Promise<User | undefined>;
  getUserByTelegramId(telegramId: string): Promise<User | undefined>;
  getUserBySessionToken(sessionToken: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUser(id: number, data: Partial<InsertUser>): Promise<User | undefined>;
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
  
  // Чаты
  createChat(chat: InsertChat): Promise<Chat>;
  getChatByIds(userId: number, chatId: string): Promise<Chat | undefined>;
  updateChat(id: number, data: Partial<InsertChat>): Promise<Chat | undefined>;
  listUserChats(userId: number, limit?: number): Promise<Chat[]>;
  listAllChats(limit?: number, offset?: number): Promise<Chat[]>;
  countChats(): Promise<number>;
  
  // Сообщения
  createMessage(message: InsertMessage): Promise<Message>;
  listChatMessages(chatId: number, limit?: number): Promise<Message[]>;
  
  // Логи
  createLog(log: InsertLog): Promise<Log>;
  listLogs(limit?: number): Promise<Log[]>;
  countApiRequests(): Promise<number>;
}

export class DatabaseStorage implements IStorage {
  // Пользователи
  async getUser(id: number): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, id));
    return user;
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

  async listAdmins(): Promise<User[]> {
    return db
      .select()
      .from(users)
      .where(eq(users.isAdmin, true));
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

  // Чаты
  async createChat(chat: InsertChat): Promise<Chat> {
    const [newChat] = await db.insert(chats).values(chat).returning();
    return newChat;
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

  async updateChat(id: number, data: Partial<InsertChat>): Promise<Chat | undefined> {
    const [updatedChat] = await db
      .update(chats)
      .set({ ...data, lastUpdated: new Date() })
      .where(eq(chats.id, id))
      .returning();
    
    return updatedChat;
  }

  async listUserChats(userId: number, limit = 5): Promise<Chat[]> {
    return db
      .select()
      .from(chats)
      .where(eq(chats.userId, userId))
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

  async listChatMessages(chatId: number, limit = 20): Promise<Message[]> {
    return db
      .select()
      .from(messages)
      .where(eq(messages.chatId, chatId))
      .orderBy(desc(messages.timestamp))
      .limit(limit);
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

  async countApiRequests(): Promise<number> {
    const [result] = await db
      .select({ count: sql<number>`count(*)` })
      .from(logs)
      .where(eq(logs.action, 'api_request'));
    
    return result?.count || 0;
  }
}

export const storage = new DatabaseStorage();
