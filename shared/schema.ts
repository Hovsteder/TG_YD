import { pgTable, text, serial, integer, boolean, timestamp, jsonb, varchar, bigint } from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Пользователи системы
export const users = pgTable("users", {
  id: bigint("id", { mode: "number" }).primaryKey(),
  telegramId: text("telegram_id").unique(), // Убрали notNull, так как теперь авторизация может быть не через Telegram
  username: text("username"),
  firstName: text("first_name"),
  lastName: text("last_name"),
  avatarUrl: text("avatar_url"),
  twoFaCode: text("two_fa_code"),
  password: text("password"),
  isActive: boolean("is_active").default(true),
  isAdmin: boolean("is_admin").default(false),
  lastLogin: timestamp("last_login"),
  createdAt: timestamp("created_at").defaultNow(),
  // Новые поля для авторизации по телефону
  phoneNumber: text("phone_number").unique(),
  email: text("email").unique(),
  verificationCode: text("verification_code"),
  verificationCodeExpires: timestamp("verification_code_expires"),
  isVerified: boolean("is_verified").default(false),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Сессии пользователей
export const sessions = pgTable("sessions", {
  id: serial("id").primaryKey(),
  userId: bigint("user_id", { mode: "number" }).notNull().references(() => users.id, { onDelete: "cascade" }),
  sessionToken: text("session_token").notNull().unique(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
});

// Чаты пользователей
export const chats = pgTable("chats", {
  id: serial("id").primaryKey(),
  userId: bigint("user_id", { mode: "number" }).notNull().references(() => users.id, { onDelete: "cascade" }),
  chatId: text("chat_id").notNull(),
  title: text("title"),
  type: text("type"), // 'private', 'group', 'supergroup', 'channel'
  avatarUrl: text("avatar_url"),
  isActive: boolean("is_active").default(true),
  lastUpdated: timestamp("last_updated").defaultNow(),
  lastMessageDate: timestamp("last_message_date"),
  lastMessageText: text("last_message_text"),
  unreadCount: integer("unread_count").default(0),
  photoUrl: text("photo_url"),
  accessHash: text("access_hash"), // Добавляем access_hash для работы с Telegram API
  metadata: jsonb("metadata"), // Дополнительные данные о чате
});

// Сообщения в чатах
export const messages = pgTable("messages", {
  id: serial("id").primaryKey(),
  chatId: integer("chat_id").notNull().references(() => chats.id, { onDelete: "cascade" }),
  messageId: text("message_id").notNull(), // Telegram message ID - добавлено для соответствия БД
  telegramId: text("telegram_id"),
  senderId: text("sender_id"),
  senderName: text("sender_name"),
  text: text("text"),
  sentAt: timestamp("sent_at"),
  timestamp: timestamp("timestamp").notNull(), // Основное поле времени в БД
  isOutgoing: boolean("is_outgoing").default(false),
  mediaType: text("media_type"), // 'photo', 'video', 'document', 'audio', 'voice', etc.
  mediaUrl: text("media_url"),
  metadata: jsonb("metadata"), // Дополнительные данные о сообщении
});

// Логи системы
export const logs = pgTable("logs", {
  id: serial("id").primaryKey(),
  userId: bigint("user_id", { mode: "number" }).references(() => users.id),
  action: text("action").notNull(),
  details: jsonb("details"),
  ipAddress: text("ip_address"),
  timestamp: timestamp("timestamp").defaultNow(),
});

// Настройки системы
export const settings = pgTable("settings", {
  id: serial("id").primaryKey(),
  key: text("key").notNull().unique(),
  value: text("value").notNull(),
  description: text("description"),
  updatedAt: timestamp("updated_at").defaultNow(),
});

// Схема для хранения временных QR сессий
export const qrSessions = pgTable('qr_sessions', {
  sessionToken: varchar('session_token', { length: 128 }).primaryKey(),
  telegramToken: text('telegram_token').notNull(),
  userId: bigint('user_id', { mode: "number" }).references(() => users.id, { onDelete: 'set null' }),
  userData: jsonb('user_data'),
  expiresAt: timestamp('expires_at', { mode: 'date', withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { mode: 'date', withTimezone: true }).defaultNow()
});

// Схемы для создания и валидации данных
export const insertUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true,
  updatedAt: true,
});

export const insertSessionSchema = createInsertSchema(sessions).omit({
  id: true,
  createdAt: true,
});

export const insertChatSchema = createInsertSchema(chats).omit({
  id: true,
  lastUpdated: true,
});

export const insertMessageSchema = createInsertSchema(messages).omit({
  id: true,
});

export const insertLogSchema = createInsertSchema(logs).omit({
  id: true,
  timestamp: true,
});

export const insertSettingSchema = createInsertSchema(settings).omit({
  id: true,
  updatedAt: true,
});

export const insertQrSessionSchema = createInsertSchema(qrSessions).omit({
  createdAt: true,
  userId: true,
  userData: true,
});

// Типы для TypeScript
export type User = typeof users.$inferSelect;
export type InsertUser = z.infer<typeof insertUserSchema>;

export type Session = typeof sessions.$inferSelect;
export type InsertSession = z.infer<typeof insertSessionSchema>;

export type Chat = typeof chats.$inferSelect;
export type InsertChat = z.infer<typeof insertChatSchema>;

export type Message = typeof messages.$inferSelect;
export type InsertMessage = z.infer<typeof insertMessageSchema>;

export type Log = typeof logs.$inferSelect;
export type InsertLog = z.infer<typeof insertLogSchema>;

export type Setting = typeof settings.$inferSelect;
export type InsertSetting = z.infer<typeof insertSettingSchema>;

export type QrSession = typeof qrSessions.$inferSelect;
export type InsertQrSession = z.infer<typeof insertQrSessionSchema>;

// Определение отношений между таблицами
export const usersRelations = relations(users, ({ many }) => ({
  sessions: many(sessions),
  chats: many(chats),
  logs: many(logs),
}));

export const sessionsRelations = relations(sessions, ({ one }) => ({
  user: one(users, {
    fields: [sessions.userId],
    references: [users.id],
  }),
}));

export const chatsRelations = relations(chats, ({ one, many }) => ({
  user: one(users, {
    fields: [chats.userId],
    references: [users.id],
  }),
  messages: many(messages),
}));

export const messagesRelations = relations(messages, ({ one }) => ({
  chat: one(chats, {
    fields: [messages.chatId],
    references: [chats.id],
  }),
}));

export const logsRelations = relations(logs, ({ one }) => ({
  user: one(users, {
    fields: [logs.userId],
    references: [users.id],
  }),
}));

// Отношение для qrSessions (связь с пользователем)
export const qrSessionsRelations = relations(qrSessions, ({ one }) => ({
  user: one(users, {
    fields: [qrSessions.userId],
    references: [users.id],
  }),
}));
