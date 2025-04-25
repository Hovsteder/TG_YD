import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogClose
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";

interface Chat {
  id: number;
  userId: number;
  chatId: string;
  title: string;
  type: string; // "private", "group", "supergroup", "channel"
  avatarUrl?: string;
  lastMessage?: string;
  lastMessageTime?: string;
  unreadCount?: number;
  messagesCount: number;
  createdAt: string;
  user?: {
    id: number;
    username?: string;
    firstName?: string;
    lastName?: string;
    avatarUrl?: string;
  };
}

interface Message {
  id: number;
  chatId: number;
  messageId: string;
  senderId: string;
  senderName: string;
  text: string;
  mediaType?: string;
  mediaUrl?: string;
  timestamp: string;
  isIncoming: boolean;
}

interface ChatsData {
  chats: Chat[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
  };
}

interface ChatsTableProps {
  chatsData?: ChatsData;
  loading: boolean;
}

export default function ChatsTable({ chatsData, loading }: ChatsTableProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedChat, setSelectedChat] = useState<Chat | null>(null);
  const [showMessageDialog, setShowMessageDialog] = useState(false);
  
  // Запрос сообщений выбранного чата
  const { data: messages, isLoading: messagesLoading } = useQuery({
    queryKey: ["/api/admin/chats", selectedChat?.id, "messages"],
    enabled: !!selectedChat && showMessageDialog,
  });

  // Обработчик просмотра сообщений чата
  const handleViewMessages = (chat: Chat) => {
    setSelectedChat(chat);
    setShowMessageDialog(true);
  };

  // Отображение состояния загрузки
  if (loading) {
    return (
      <Card>
        <CardHeader className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
          <h2 className="font-medium text-lg">Чаты пользователей</h2>
          <div className="flex items-center">
            <Skeleton className="w-64 h-10 mr-4" />
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Чат</TableHead>
                  <TableHead>Пользователь</TableHead>
                  <TableHead>Тип</TableHead>
                  <TableHead>Сообщений</TableHead>
                  <TableHead>Последнее сообщение</TableHead>
                  <TableHead>Действия</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {Array(5)
                  .fill(0)
                  .map((_, i) => (
                    <TableRow key={i}>
                      <TableCell>
                        <div className="flex items-center">
                          <Skeleton className="w-10 h-10 rounded-full" />
                          <div className="ml-3">
                            <Skeleton className="h-4 w-24 mb-1" />
                            <Skeleton className="h-3 w-16" />
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center">
                          <Skeleton className="w-8 h-8 rounded-full" />
                          <Skeleton className="h-4 w-24 ml-2" />
                        </div>
                      </TableCell>
                      <TableCell>
                        <Skeleton className="h-5 w-16 rounded-full" />
                      </TableCell>
                      <TableCell>
                        <Skeleton className="h-4 w-10" />
                      </TableCell>
                      <TableCell>
                        <Skeleton className="h-4 w-48" />
                      </TableCell>
                      <TableCell>
                        <Skeleton className="h-8 w-24 rounded" />
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    );
  }

  // Если данных нет
  if (!chatsData || chatsData.chats.length === 0) {
    return (
      <Card>
        <CardHeader className="px-6 py-4 border-b border-gray-200">
          <h2 className="font-medium text-lg">Чаты пользователей</h2>
        </CardHeader>
        <CardContent className="p-6 text-center">
          <div className="flex flex-col items-center justify-center py-8">
            <span className="material-icons text-neutral-gray text-4xl mb-4">
              chat_bubble_outline
            </span>
            <p className="text-neutral-gray">Чаты отсутствуют</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  // Фильтрация чатов по поисковому запросу
  const filteredChats = chatsData.chats.filter(
    (chat) =>
      chat.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      chat.user?.username?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      chat.user?.firstName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      chat.chatId.includes(searchTerm)
  );

  // Получение названия типа чата
  const getChatTypeLabel = (type: string) => {
    switch (type) {
      case "private":
        return { label: "Личный", color: "bg-purple-100 text-purple-800" };
      case "group":
        return { label: "Группа", color: "bg-green-100 text-green-800" };
      case "supergroup":
        return { label: "Супергруппа", color: "bg-blue-100 text-blue-800" };
      case "channel":
        return { label: "Канал", color: "bg-orange-100 text-orange-800" };
      default:
        return { label: type, color: "bg-gray-100 text-gray-800" };
    }
  };

  return (
    <>
      <Card>
        <CardHeader className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
          <h2 className="font-medium text-lg">Чаты пользователей</h2>
          <div className="flex items-center">
            <div className="relative">
              <Input
                type="text"
                placeholder="Поиск по названию, пользователю"
                className="w-64 py-2 px-4 pr-10 border border-gray-300 rounded-lg focus:outline-none focus:border-telegram-blue"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
              <span className="material-icons absolute right-3 top-1/2 transform -translate-y-1/2 text-neutral-gray">
                search
              </span>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="bg-neutral-light border-b border-gray-200">
                  <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                    Чат
                  </TableHead>
                  <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                    Пользователь
                  </TableHead>
                  <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                    Тип
                  </TableHead>
                  <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                    Сообщений
                  </TableHead>
                  <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                    Последнее сообщение
                  </TableHead>
                  <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                    Действия
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody className="bg-white divide-y divide-gray-200">
                {filteredChats.map((chat) => {
                  const typeInfo = getChatTypeLabel(chat.type);
                  
                  return (
                    <TableRow key={chat.id} className="hover:bg-neutral-light">
                      <TableCell className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          {chat.avatarUrl ? (
                            <img
                              src={chat.avatarUrl}
                              alt={`Аватар чата ${chat.title}`}
                              className="w-10 h-10 rounded-full"
                            />
                          ) : (
                            <div className="w-10 h-10 rounded-full bg-telegram-light flex items-center justify-center">
                              <span className="material-icons text-telegram-blue">
                                {chat.type === "private" ? "person" : chat.type === "channel" ? "campaign" : "group"}
                              </span>
                            </div>
                          )}
                          <div className="ml-3">
                            <p className="text-sm font-medium text-neutral-dark">{chat.title}</p>
                            <p className="text-xs text-neutral-gray">ID: {chat.chatId}</p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          {chat.user?.avatarUrl ? (
                            <img
                              src={chat.user.avatarUrl}
                              alt="Аватар пользователя"
                              className="w-8 h-8 rounded-full"
                            />
                          ) : (
                            <div className="w-8 h-8 rounded-full bg-telegram-light flex items-center justify-center">
                              <span className="material-icons text-telegram-blue text-sm">
                                person
                              </span>
                            </div>
                          )}
                          <div className="ml-2">
                            <p className="text-sm font-medium text-neutral-dark">
                              {chat.user?.firstName} {chat.user?.lastName || ""}
                            </p>
                            {chat.user?.username && (
                              <p className="text-xs text-neutral-gray">
                                @{chat.user.username}
                              </p>
                            )}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${typeInfo.color}`}>
                          {typeInfo.label}
                        </span>
                      </TableCell>
                      <TableCell className="px-6 py-4 whitespace-nowrap text-sm text-neutral-dark">
                        {chat.messagesCount || 0}
                      </TableCell>
                      <TableCell className="px-6 py-4 text-sm text-neutral-gray max-w-xs">
                        <div>
                          <p className="truncate">
                            {chat.lastMessage || "Нет сообщений"}
                          </p>
                          {chat.lastMessageTime && (
                            <p className="text-xs mt-1">
                              {new Date(chat.lastMessageTime).toLocaleString("ru-RU")}
                            </p>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="px-6 py-4 whitespace-nowrap text-sm">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleViewMessages(chat)}
                          className="flex items-center"
                        >
                          <span
                            className="material-icons mr-1"
                            style={{ fontSize: "16px" }}
                          >
                            chat
                          </span>
                          Сообщения
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Диалог с сообщениями чата */}
      <Dialog open={showMessageDialog} onOpenChange={setShowMessageDialog}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-hidden flex flex-col">
          <DialogHeader>
            <DialogTitle className="flex items-center">
              {selectedChat?.avatarUrl ? (
                <img
                  src={selectedChat.avatarUrl}
                  alt={`Аватар чата ${selectedChat.title}`}
                  className="w-8 h-8 rounded-full mr-2"
                />
              ) : (
                <div className="w-8 h-8 rounded-full bg-telegram-light flex items-center justify-center mr-2">
                  <span className="material-icons text-telegram-blue text-sm">
                    {selectedChat?.type === "private" ? "person" : selectedChat?.type === "channel" ? "campaign" : "group"}
                  </span>
                </div>
              )}
              {selectedChat?.title}
            </DialogTitle>
            <DialogDescription>
              {selectedChat?.user?.firstName} {selectedChat?.user?.lastName} 
              {selectedChat?.user?.username && `(@${selectedChat.user.username})`} • 
              {getChatTypeLabel(selectedChat?.type || "").label}
            </DialogDescription>
          </DialogHeader>
          
          <div className="mt-4 flex-grow overflow-y-auto">
            {messagesLoading ? (
              <div className="flex flex-col space-y-3 p-4">
                {Array(5).fill(0).map((_, i) => (
                  <div key={i} className={`flex ${i % 2 === 0 ? 'justify-start' : 'justify-end'}`}>
                    <div className={`max-w-[70%] ${i % 2 === 0 ? 'bg-neutral-medium' : 'bg-telegram-light'} rounded-lg p-3`}>
                      <Skeleton className="h-4 w-32 mb-2" />
                      <Skeleton className="h-16 w-full" />
                      <div className="flex justify-between items-center mt-2">
                        <Skeleton className="h-3 w-24" />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : messages && messages.length > 0 ? (
              <div className="flex flex-col space-y-3 p-4">
                {messages.map((message: Message) => (
                  <div key={message.id} className={`flex ${message.isIncoming ? 'justify-start' : 'justify-end'}`}>
                    <div className={`max-w-[70%] ${message.isIncoming ? 'bg-neutral-medium' : 'bg-telegram-light'} rounded-lg p-3`}>
                      <p className="text-sm font-medium text-neutral-dark">{message.senderName}</p>
                      <p className="text-sm mt-1">{message.text}</p>
                      
                      {message.mediaType && (
                        <div className="mt-2 border rounded p-2 bg-white">
                          <div className="flex items-center">
                            <span className="material-icons text-neutral-gray mr-2" style={{ fontSize: "18px" }}>
                              {message.mediaType === "photo" ? "image" :
                               message.mediaType === "video" ? "videocam" :
                               message.mediaType === "document" ? "insert_drive_file" :
                               message.mediaType === "audio" ? "audiotrack" : "attachment"}
                            </span>
                            <span className="text-sm text-neutral-gray">
                              {message.mediaType === "photo" ? "Фотография" :
                               message.mediaType === "video" ? "Видео" :
                               message.mediaType === "document" ? "Документ" :
                               message.mediaType === "audio" ? "Аудио" : "Медиафайл"}
                            </span>
                          </div>
                        </div>
                      )}
                      
                      <div className="flex justify-between items-center mt-2">
                        <span className="text-xs text-neutral-gray">
                          {new Date(message.timestamp).toLocaleString("ru-RU")}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-12">
                <span className="material-icons text-neutral-gray text-4xl mb-4">
                  chat_bubble_outline
                </span>
                <p className="text-neutral-gray">Сообщения отсутствуют</p>
              </div>
            )}
          </div>
          
          <div className="mt-4 border-t pt-4 flex justify-end">
            <DialogClose asChild>
              <Button variant="secondary">Закрыть</Button>
            </DialogClose>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}