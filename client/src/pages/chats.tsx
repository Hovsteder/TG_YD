import { useEffect, useState } from "react";
import { useAuth } from "@/context/auth-context";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { useQuery } from "@tanstack/react-query";
import { Chat, Message } from "../../../shared/schema";
import { Separator } from "@/components/ui/separator";
import { Loader2, Send, MessageSquare } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useLanguage } from "@/hooks/use-language";
import { formatDistanceToNow } from "date-fns";
import { ru, enUS } from "date-fns/locale";
import NavigationMenu from "@/components/navigation-menu";

export default function ChatsPage() {
  const { user, isAuthenticated } = useAuth();
  const { toast } = useToast();
  const { t, language } = useLanguage();
  const [selectedChat, setSelectedChat] = useState<Chat | null>(null);
  const [messageText, setMessageText] = useState("");

  // Получение списка чатов
  const {
    data: chats,
    isLoading: isLoadingChats,
    error: chatsError,
    refetch: refetchChats
  } = useQuery({
    queryKey: ["/api/chats"],
    queryFn: async () => {
      const res = await apiRequest("GET", "/api/chats");
      return res.json() as Promise<Chat[]>;
    },
    enabled: isAuthenticated,
  });

  // Получение сообщений выбранного чата
  const {
    data: messages,
    isLoading: isLoadingMessages,
    refetch: refetchMessages
  } = useQuery({
    queryKey: ["/api/chats", selectedChat?.id, "messages"],
    queryFn: async () => {
      if (!selectedChat) return [];
      // Добавляем параметр update=true для обновления сообщений при каждом запросе
      const res = await apiRequest("GET", `/api/chats/${selectedChat.chatId}/messages?update=true`);
      return res.json() as Promise<Message[]>;
    },
    enabled: !!selectedChat,
  });

  // Обработчик выбора чата
  const handleSelectChat = (chat: Chat) => {
    setSelectedChat(chat);
    // При выборе чата запускаем обновление сообщений
    setTimeout(() => {
      refetchMessages();
    }, 100); // Небольшая задержка, чтобы query hook успел обновиться с новым selectedChat
  };

  // Обработчик отправки сообщения (заглушка)
  const handleSendMessage = (e: React.FormEvent) => {
    e.preventDefault();
    if (!messageText.trim() || !selectedChat) return;

    toast({
      title: t("message_sent"),
      description: t("message_sent_description"),
    });

    setMessageText("");
  };

  // Форматирование даты с учетом языка
  const formatDate = (date: Date | null) => {
    if (!date) return '';
    return formatDistanceToNow(new Date(date), { 
      addSuffix: true, 
      locale: language === 'ru' ? ru : enUS 
    });
  };

  // Обработка ошибок и автоматическое обновление при загрузке страницы
  useEffect(() => {
    if (chatsError) {
      toast({
        title: t("error_loading_chats"),
        description: t("error_loading_chats_description"),
        variant: "destructive",
      });
    }
  }, [chatsError, toast, t]);
  
  // Обновляем список чатов при монтировании компонента
  useEffect(() => {
    if (isAuthenticated) {
      refetchChats();
    }
  }, [isAuthenticated, refetchChats]);

  if (!isAuthenticated) {
    return (
      <div className="flex flex-col items-center justify-center min-h-screen p-4">
        <h1 className="text-2xl font-bold mb-4">{t("not_authenticated")}</h1>
        <p>{t("please_login")}</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-screen max-h-screen bg-background">
      <NavigationMenu />
      <div className="p-4 border-b">
        <h1 className="text-2xl font-bold">{t("your_chats")}</h1>
        <p className="text-muted-foreground">{t("logged_in_as")} {user?.username || user?.firstName}</p>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Список чатов */}
        <div className="w-1/3 border-r overflow-hidden flex flex-col">
          <div className="p-3 border-b bg-muted/30">
            <h2 className="font-medium">{t("recent_chats")}</h2>
          </div>
          
          <ScrollArea className="flex-1">
            {isLoadingChats ? (
              <div className="flex justify-center items-center h-full">
                <Loader2 className="h-8 w-8 animate-spin text-primary" />
              </div>
            ) : chats && chats.length > 0 ? (
              <div>
                {chats.map((chat) => (
                  <div
                    key={chat.id}
                    className={`p-3 flex items-center space-x-3 cursor-pointer hover:bg-muted/50 transition-colors ${
                      selectedChat?.id === chat.id ? "bg-muted" : ""
                    }`}
                    onClick={() => handleSelectChat(chat)}
                  >
                    <Avatar>
                      <AvatarImage src={chat.photoUrl || ""} />
                      <AvatarFallback>
                        {(chat.title || "CH").substring(0, 2).toUpperCase()}
                      </AvatarFallback>
                    </Avatar>
                    <div className="flex-1 min-w-0">
                      <div className="flex justify-between">
                        <h3 className="font-medium truncate">{chat.title || t("unknown")}</h3>
                        {chat.lastMessageDate && (
                          <span className="text-xs text-muted-foreground whitespace-nowrap">
                            {formatDate(chat.lastMessageDate)}
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground truncate">
                        {chat.lastMessageText || t("no_messages")}
                      </p>
                    </div>
                    {chat.unreadCount && chat.unreadCount > 0 && (
                      <div className="bg-primary text-primary-foreground rounded-full px-2 py-0.5 text-xs font-medium">
                        {chat.unreadCount}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-full p-4 text-center">
                <MessageSquare className="h-12 w-12 text-muted-foreground mb-2" />
                <h3 className="font-medium">{t("no_chats_found")}</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  {t("no_chats_description")}
                </p>
              </div>
            )}
          </ScrollArea>
        </div>

        {/* Область чата и сообщений */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {selectedChat ? (
            <>
              <div className="p-3 border-b flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <Avatar>
                    <AvatarImage src={selectedChat.photoUrl || ""} />
                    <AvatarFallback>
                      {(selectedChat.title || "CH").substring(0, 2).toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                  <div>
                    <h2 className="font-medium">{selectedChat.title || t("unknown")}</h2>
                    <p className="text-xs text-muted-foreground">
                      {selectedChat.type === "private"
                        ? t("private_chat")
                        : selectedChat.type === "group"
                        ? t("group")
                        : t("channel")}
                    </p>
                  </div>
                </div>
                <Button 
                  variant="ghost" 
                  size="icon" 
                  onClick={() => refetchMessages()}
                  title={t("refresh_messages")}
                  disabled={isLoadingMessages}
                >
                  {isLoadingMessages ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M21 2v6h-6"></path>
                      <path d="M3 12a9 9 0 0 1 15-6.7L21 8"></path>
                      <path d="M3 22v-6h6"></path>
                      <path d="M21 12a9 9 0 0 1-15 6.7L3 16"></path>
                    </svg>
                  )}
                </Button>
              </div>

              <ScrollArea className="flex-1 p-4">
                {isLoadingMessages ? (
                  <div className="flex justify-center items-center h-full">
                    <Loader2 className="h-8 w-8 animate-spin text-primary" />
                  </div>
                ) : messages && messages.length > 0 ? (
                  <div className="space-y-4">
                    {messages.map((message) => (
                      <div
                        key={message.id}
                        className={`flex ${
                          message.isOutgoing
                            ? "justify-end"
                            : "justify-start"
                        }`}
                      >
                        <div
                          className={`max-w-[80%] rounded-lg p-3 ${
                            message.isOutgoing
                              ? "bg-primary text-primary-foreground"
                              : "bg-muted"
                          }`}
                        >
                          {!message.isOutgoing && (
                            <p className="text-xs font-medium mb-1">
                              {message.senderName || t("unknown")}
                            </p>
                          )}
                          <p className="break-words">{message.text}</p>
                          <p className="text-xs mt-1 opacity-70 text-right">
                            {formatDate(message.sentAt)}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center h-full text-center">
                    <MessageSquare className="h-12 w-12 text-muted-foreground mb-2" />
                    <h3 className="font-medium">{t("no_messages")}</h3>
                    <p className="text-sm text-muted-foreground mt-1">
                      {t("start_conversation")}
                    </p>
                  </div>
                )}
              </ScrollArea>

              <div className="p-3 border-t">
                <form
                  onSubmit={handleSendMessage}
                  className="flex items-center space-x-2"
                >
                  <Input
                    value={messageText}
                    onChange={(e) => setMessageText(e.target.value)}
                    placeholder={t("type_message")}
                    className="flex-1"
                  />
                  <Button type="submit" size="icon">
                    <Send className="h-4 w-4" />
                  </Button>
                </form>
              </div>
            </>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-center p-4">
              <MessageSquare className="h-16 w-16 text-muted-foreground mb-4" />
              <h2 className="text-xl font-medium">{t("select_chat")}</h2>
              <p className="text-muted-foreground mt-2 max-w-md">
                {t("select_chat_description")}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}