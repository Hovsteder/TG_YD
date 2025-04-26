import { pgTable, text, serial, integer, boolean, timestamp, jsonb } from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Пользователи системы
export const users = pgTable("users", {
  id: serial("id").primaryKey(),
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
});

// Сессии пользователей
export const sessions = pgTable("sessions", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  sessionToken: text("session_token").notNull().unique(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
});

// Чаты пользователей
export const chats = pgTable("chats", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
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
  isOutgoing: boolean("is_outgoing").default(false),
  mediaType: text("media_type"), // 'photo', 'video', 'document', 'audio', 'voice', etc.
  mediaUrl: text("media_url"),
  metadata: jsonb("metadata"), // Дополнительные данные о сообщении
});

// Логи системы
export const logs = pgTable("logs", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id),
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

// Схемы для создания и валидации данных
export const insertUserSchema = createInsertSchema(users).omit({
  id: true,
  createdAt: true,
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
