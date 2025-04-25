import { useMemo } from "react";
import { Chat } from "@/pages/dashboard";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

interface ChatListProps {
  chats: Chat[];
  selectedChat: Chat | null;
  onSelectChat: (chat: Chat) => void;
  loading: boolean;
}

export default function ChatList({
  chats,
  selectedChat,
  onSelectChat,
  loading,
}: ChatListProps) {
  // Мемоизируем последние 5 чатов
  const recentChats = useMemo(() => {
    return chats?.slice(0, 5) || [];
  }, [chats]);

  // Отображение состояния загрузки
  if (loading) {
    return (
      <Card>
        <CardHeader className="p-4 bg-telegram-light border-b border-gray-200">
          <h2 className="font-medium">Последние чаты</h2>
        </CardHeader>
        <CardContent className="p-0 divide-y divide-gray-200">
          {Array(5)
            .fill(0)
            .map((_, index) => (
              <div key={index} className="p-3">
                <div className="flex items-center">
                  <Skeleton className="w-12 h-12 rounded-full" />
                  <div className="ml-3 flex-grow">
                    <div className="flex justify-between items-center">
                      <Skeleton className="h-4 w-32" />
                      <Skeleton className="h-3 w-10" />
                    </div>
                    <div className="flex justify-between items-center mt-1">
                      <Skeleton className="h-3 w-48" />
                    </div>
                  </div>
                </div>
              </div>
            ))}
        </CardContent>
      </Card>
    );
  }

  // Отображение пустого списка
  if (!recentChats.length) {
    return (
      <Card>
        <CardHeader className="p-4 bg-telegram-light border-b border-gray-200">
          <h2 className="font-medium">Последние чаты</h2>
        </CardHeader>
        <CardContent className="p-6 text-center">
          <div className="flex flex-col items-center justify-center py-8">
            <span className="material-icons text-neutral-gray text-4xl mb-4">
              chat_bubble_outline
            </span>
            <p className="text-neutral-gray">У вас пока нет чатов</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="p-4 bg-telegram-light border-b border-gray-200">
        <h2 className="font-medium">Последние чаты</h2>
      </CardHeader>
      <CardContent className="p-0 divide-y divide-gray-200">
        {recentChats.map((chat) => (
          <div
            key={chat.id}
            className={`p-3 hover:bg-neutral-medium cursor-pointer transition-colors ${
              selectedChat?.id === chat.id ? "bg-neutral-medium" : ""
            }`}
            onClick={() => onSelectChat(chat)}
          >
            <div className="flex items-center">
              <div className="relative">
                {chat.avatarUrl ? (
                  <img
                    src={chat.avatarUrl}
                    alt={`Аватар ${chat.title}`}
                    className="w-12 h-12 rounded-full"
                  />
                ) : (
                  <div className="w-12 h-12 rounded-full bg-telegram-light flex items-center justify-center">
                    <span className="material-icons text-telegram-blue">
                      {chat.type === "private" ? "person" : "group"}
                    </span>
                  </div>
                )}
                {chat.isOnline && (
                  <span className="absolute bottom-0 right-0 w-3 h-3 bg-status-green rounded-full border-2 border-white"></span>
                )}
              </div>
              <div className="ml-3 flex-grow">
                <div className="flex justify-between items-center">
                  <h3 className="font-medium text-neutral-dark truncate max-w-[150px]">
                    {chat.title}
                  </h3>
                  {chat.lastMessageTime && (
                    <span className="text-xs text-neutral-gray">
                      {chat.lastMessageTime}
                    </span>
                  )}
                </div>
                <div className="flex justify-between items-center">
                  <p className="text-sm text-neutral-gray truncate max-w-[180px]">
                    {chat.lastMessage || "Нет сообщений"}
                  </p>
                  {chat.unreadCount && chat.unreadCount > 0 && (
                    <div className="ml-2 flex-shrink-0">
                      <span className="inline-flex items-center justify-center w-5 h-5 bg-telegram-blue rounded-full text-xs text-white">
                        {chat.unreadCount}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
