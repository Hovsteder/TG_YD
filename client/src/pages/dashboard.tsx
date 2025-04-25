import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { useAuth } from "@/context/auth-context";
import Header from "@/components/layout/header";
import ChatList from "@/components/chat-list";
import ChatView from "@/components/chat-view";

// Интерфейс сообщения
export interface Message {
  id: number;
  messageId: string;
  senderId: string;
  senderName: string;
  text: string;
  mediaType?: string;
  mediaUrl?: string;
  timestamp: string;
  isIncoming: boolean;
}

// Интерфейс чата
export interface Chat {
  id: number;
  chatId: string;
  title: string;
  type: string;
  avatarUrl?: string;
  lastMessage?: string;
  lastMessageTime?: string;
  unreadCount?: number;
  isOnline?: boolean;
  messages?: Message[];
}

export default function DashboardPage() {
  const { user, isAuthenticated, loading, logout } = useAuth();
  const [, navigate] = useLocation();
  const [selectedChat, setSelectedChat] = useState<Chat | null>(null);

  // Проверка авторизации
  useEffect(() => {
    if (!isAuthenticated && !loading) {
      navigate("/");
    }
  }, [isAuthenticated, loading, navigate]);

  // Запрос списка чатов
  const { data: chats = [], isLoading: chatsLoading } = useQuery({
    queryKey: ["/api/chats"],
    enabled: isAuthenticated,
  });

  // Запрос сообщений выбранного чата
  const { data: messages = [], isLoading: messagesLoading } = useQuery({
    queryKey: [selectedChat ? `/api/chats/${selectedChat.chatId}/messages` : null],
    enabled: !!selectedChat,
  });

  // Обработчик выбора чата
  const handleSelectChat = (chat: Chat) => {
    setSelectedChat(chat);
  };

  // Если идет загрузка или пользователь не авторизован, показываем заглушку
  if (loading || !isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-neutral-medium">
        <div className="text-center">
          <span className="material-icons text-4xl text-telegram-blue animate-pulse">
            hourglass_top
          </span>
          <p className="mt-2 text-neutral-gray">Загрузка...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-neutral-medium">
      {/* Шапка */}
      <Header user={user} onLogout={logout} />

      {/* Основной контент */}
      <main className="container mx-auto px-4 py-6">
        <div className="flex flex-col md:flex-row gap-6">
          {/* Сайдбар со списком чатов */}
          <div className="w-full md:w-1/3 lg:w-1/4">
            <ChatList
              chats={chats}
              selectedChat={selectedChat}
              onSelectChat={handleSelectChat}
              loading={chatsLoading}
            />
          </div>

          {/* Основное окно чата */}
          <div className="w-full md:w-2/3 lg:w-3/4">
            <ChatView
              chat={selectedChat}
              messages={messages}
              loading={messagesLoading}
            />
          </div>
        </div>
      </main>
    </div>
  );
}
