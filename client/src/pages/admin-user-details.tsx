import { useState, useEffect } from "react";
import { useLocation, useRoute, Link } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
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
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";

interface User {
  id: number;
  telegramId: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  phoneNumber?: string;
  email?: string;
  avatarUrl?: string;
  isActive: boolean;
  isAdmin: boolean;
  lastLogin?: string;
  createdAt: string;
}

interface Session {
  id: number;
  userId: number;
  sessionToken: string;
  ipAddress?: string;
  userAgent?: string;
  createdAt: string;
  expiresAt: string;
}

interface Chat {
  id: number;
  userId: number;
  chatId: string;
  type: string;
  title: string;
  lastMessageDate?: string;
  lastMessageText?: string;
  unreadCount: number;
  photoUrl?: string;
}

interface Message {
  id: number;
  chatId: number;
  userId: number;
  messageId: number;
  telegramId: string;
  text: string;
  sentAt: string;
  isOutgoing: boolean;
  senderId?: string;
  senderName?: string;
}

export default function AdminUserDetailsPage() {
  const [, navigate] = useLocation();
  const [match, params] = useRoute("/admin/users/:userId");
  const { toast } = useToast();
  const [adminData, setAdminData] = useState<any>(null);
  const [selectedChat, setSelectedChat] = useState<number | null>(null);
  
  // Проверка авторизации администратора
  useEffect(() => {
    const adminToken = localStorage.getItem("admin_token");
    const adminUser = localStorage.getItem("admin_user");
    
    if (!adminToken || !adminUser) {
      navigate("/admin/login");
      return;
    }
    
    setAdminData(JSON.parse(adminUser));
  }, [navigate]);
  
  const userId = params?.userId ? parseInt(params.userId) : 0;
  
  const adminToken = localStorage.getItem("admin_token");
  const headers = {
    "Admin-Authorization": adminToken || ""
  };
  
  // Получение данных пользователя
  const { data: userData, isLoading: userLoading } = useQuery({
    queryKey: [`/api/admin/users/${userId}`],
    enabled: !!adminData && userId > 0,
    meta: { headers }
  });
  
  // Получение сессий пользователя
  const { data: userSessions, isLoading: sessionsLoading } = useQuery({
    queryKey: [`/api/admin/users/${userId}/sessions`],
    enabled: !!adminData && userId > 0,
    meta: { headers }
  });
  
  // Получение чатов пользователя
  const { data: userChats, isLoading: chatsLoading } = useQuery({
    queryKey: [`/api/admin/users/${userId}/chats`],
    enabled: !!adminData && userId > 0,
    meta: { headers }
  });
  
  // Получение сообщений выбранного чата
  const { data: chatMessages, isLoading: messagesLoading } = useQuery({
    queryKey: [`/api/admin/users/${userId}/chats/${selectedChat}/messages`],
    enabled: !!adminData && userId > 0 && selectedChat !== null,
    meta: { headers }
  });
  
  // Форматирование даты
  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('ru-RU', { 
      day: '2-digit', 
      month: '2-digit', 
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    }).format(date);
  };
  
  const handleBackToUsers = () => {
    navigate("/admin");
  };
  
  const handleSelectChat = (chatId: number) => {
    setSelectedChat(chatId);
  };
  
  // Получение имени пользователя для отображения
  const getUserName = (user?: User) => {
    if (!user) return "Пользователь";
    
    if (user.firstName || user.lastName) {
      return `${user.firstName || ""} ${user.lastName || ""}`.trim();
    }
    
    if (user.username) {
      return `@${user.username}`;
    }
    
    return `ID ${user.id}`;
  };
  
  return (
    <div className="min-h-screen bg-neutral-medium">
      {/* Шапка страницы */}
      <header className="bg-neutral-dark text-white shadow-md">
        <div className="container mx-auto px-4 py-3 flex justify-between items-center">
          <div className="flex items-center">
            <span className="material-icons mr-2">admin_panel_settings</span>
            <h1 className="font-bold text-xl">Админ-панель: Детали пользователя</h1>
          </div>
          
          <div className="flex items-center">
            <button 
              className="bg-telegram-blue hover:bg-telegram-dark text-white py-1 px-3 rounded-md flex items-center text-sm"
              onClick={handleBackToUsers}
            >
              <span className="material-icons mr-1" style={{ fontSize: "16px" }}>arrow_back</span>
              Вернуться к списку пользователей
            </button>
          </div>
        </div>
      </header>
      
      <div className="container mx-auto px-4 py-6">
        {/* Карточка с информацией о пользователе */}
        <Card className="mb-6">
          <CardHeader className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
            <h2 className="font-medium text-lg">Информация о пользователе</h2>
          </CardHeader>
          <CardContent className="p-6">
            {userLoading ? (
              <div className="flex flex-col space-y-4">
                <Skeleton className="h-8 w-48" />
                <div className="grid grid-cols-2 gap-6">
                  <Skeleton className="h-6 w-full" />
                  <Skeleton className="h-6 w-full" />
                  <Skeleton className="h-6 w-full" />
                  <Skeleton className="h-6 w-full" />
                </div>
              </div>
            ) : userData ? (
              <div>
                <div className="flex items-center mb-6">
                  {userData.avatarUrl ? (
                    <img
                      src={userData.avatarUrl}
                      alt="Аватар пользователя"
                      className="w-16 h-16 rounded-full mr-4"
                    />
                  ) : (
                    <div className="w-16 h-16 rounded-full bg-telegram-light flex items-center justify-center mr-4">
                      <span className="material-icons text-telegram-blue text-2xl">
                        person
                      </span>
                    </div>
                  )}
                  <div>
                    <h3 className="text-xl font-semibold">
                      {getUserName(userData)}
                    </h3>
                    <div className="flex items-center mt-1">
                      {userData.isActive ? (
                        <span className="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-status-green bg-opacity-10 text-status-green mr-2">
                          Активен
                        </span>
                      ) : (
                        <span className="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-status-red bg-opacity-10 text-status-red mr-2">
                          Заблокирован
                        </span>
                      )}
                      {userData.isAdmin && (
                        <span className="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-telegram-blue bg-opacity-10 text-telegram-blue">
                          Администратор
                        </span>
                      )}
                    </div>
                  </div>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <p className="text-sm text-neutral-gray mb-1">Telegram ID</p>
                    <p className="font-medium">{userData.telegramId || "—"}</p>
                  </div>
                  <div>
                    <p className="text-sm text-neutral-gray mb-1">Имя пользователя</p>
                    <p className="font-medium">
                      {userData.username ? `@${userData.username}` : "—"}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-neutral-gray mb-1">Дата регистрации</p>
                    <p className="font-medium">
                      {userData.createdAt ? formatDate(userData.createdAt) : "—"}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-neutral-gray mb-1">Последний вход</p>
                    <p className="font-medium">
                      {userData.lastLogin ? formatDate(userData.lastLogin) : "—"}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-neutral-gray mb-1">Номер телефона</p>
                    <p className="font-medium">{userData.phoneNumber || "—"}</p>
                  </div>
                  <div>
                    <p className="text-sm text-neutral-gray mb-1">Email</p>
                    <p className="font-medium">{userData.email || "—"}</p>
                  </div>
                </div>
              </div>
            ) : (
              <div className="text-center py-6">
                <span className="material-icons text-neutral-gray text-4xl mb-4">
                  person_outline
                </span>
                <p className="text-neutral-gray">Пользователь не найден</p>
              </div>
            )}
          </CardContent>
        </Card>
        
        {/* Вкладки для отображения чатов, сессий и других данных */}
        <Tabs defaultValue="chats">
          <TabsList className="mb-4">
            <TabsTrigger value="chats">Чаты</TabsTrigger>
            <TabsTrigger value="sessions">Сессии</TabsTrigger>
          </TabsList>
          
          {/* Вкладка с чатами и сообщениями */}
          <TabsContent value="chats">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Список чатов */}
              <Card className="col-span-1">
                <CardHeader className="px-6 py-4 border-b border-gray-200">
                  <h3 className="font-medium">Список чатов</h3>
                </CardHeader>
                <CardContent className="p-0">
                  {chatsLoading ? (
                    <div className="p-4 space-y-4">
                      {Array(5).fill(0).map((_, i) => (
                        <div key={i} className="flex items-center space-x-3">
                          <Skeleton className="w-10 h-10 rounded-full" />
                          <div className="space-y-2">
                            <Skeleton className="h-4 w-40" />
                            <Skeleton className="h-3 w-24" />
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : !userChats || userChats.length === 0 ? (
                    <div className="flex flex-col items-center justify-center p-6 text-center">
                      <span className="material-icons text-neutral-gray text-4xl mb-4">
                        question_answer
                      </span>
                      <p className="text-neutral-gray">Чаты не найдены</p>
                    </div>
                  ) : (
                    <div className="divide-y divide-gray-200 max-h-[400px] overflow-auto">
                      {userChats.map((chat: Chat) => (
                        <div 
                          key={chat.id} 
                          className={`p-4 flex items-center cursor-pointer hover:bg-neutral-light ${
                            selectedChat === chat.id ? "bg-neutral-light" : ""
                          }`}
                          onClick={() => handleSelectChat(chat.id)}
                        >
                          {chat.photoUrl ? (
                            <img
                              src={chat.photoUrl}
                              alt={chat.title}
                              className="w-10 h-10 rounded-full"
                            />
                          ) : (
                            <div className="w-10 h-10 rounded-full bg-telegram-light flex items-center justify-center">
                              <span className="material-icons text-telegram-blue text-sm">
                                {chat.type === "private" ? "person" : chat.type === "channel" ? "campaign" : "group"}
                              </span>
                            </div>
                          )}
                          <div className="ml-3">
                            <p className="text-sm font-medium text-neutral-dark">
                              {chat.title}
                            </p>
                            <p className="text-xs text-neutral-gray truncate max-w-[200px]">
                              {chat.lastMessageText || "Нет сообщений"}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
              
              {/* Сообщения выбранного чата */}
              <Card className="col-span-1 lg:col-span-2">
                <CardHeader className="px-6 py-4 border-b border-gray-200">
                  <h3 className="font-medium">
                    {selectedChat === null
                      ? "Выберите чат для просмотра сообщений"
                      : userChats?.find((chat: Chat) => chat.id === selectedChat)?.title || "Сообщения"}
                  </h3>
                </CardHeader>
                <CardContent className="p-0">
                  {selectedChat === null ? (
                    <div className="flex flex-col items-center justify-center p-12 text-center">
                      <span className="material-icons text-neutral-gray text-4xl mb-4">
                        chat
                      </span>
                      <p className="text-neutral-gray">Выберите чат из списка для просмотра сообщений</p>
                    </div>
                  ) : messagesLoading ? (
                    <div className="p-4 space-y-6">
                      {Array(5).fill(0).map((_, i) => (
                        <div key={i} className={`flex ${i % 2 === 0 ? "justify-start" : "justify-end"}`}>
                          <div className={`max-w-md ${i % 2 === 0 ? "bg-neutral-light" : "bg-telegram-light"} rounded-lg p-3`}>
                            <Skeleton className="h-4 w-24 mb-2" />
                            <Skeleton className="h-4 w-full" />
                            <Skeleton className="h-4 w-32 mt-2" />
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : !chatMessages || chatMessages.length === 0 ? (
                    <div className="flex flex-col items-center justify-center p-12 text-center">
                      <span className="material-icons text-neutral-gray text-4xl mb-4">
                        forum
                      </span>
                      <p className="text-neutral-gray">Сообщения не найдены</p>
                    </div>
                  ) : (
                    <div className="p-4 space-y-4 max-h-[500px] overflow-auto">
                      {chatMessages.map((message: Message) => (
                        <div key={message.id} className={`flex ${message.isOutgoing ? "justify-end" : "justify-start"}`}>
                          <div 
                            className={`max-w-md rounded-lg p-3 ${
                              message.isOutgoing ? "bg-telegram-light text-telegram-dark" : "bg-neutral-light"
                            }`}
                          >
                            {message.senderName && !message.isOutgoing && (
                              <p className="text-xs font-semibold mb-1 text-telegram-blue">
                                {message.senderName}
                              </p>
                            )}
                            <p className="text-sm whitespace-pre-wrap">{message.text}</p>
                            <p className="text-xs text-neutral-gray text-right mt-1">
                              {new Date(message.sentAt).toLocaleTimeString('ru-RU', {
                                hour: '2-digit',
                                minute: '2-digit'
                              })}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>
          
          {/* Вкладка с сессиями */}
          <TabsContent value="sessions">
            <Card>
              <CardHeader className="px-6 py-4 border-b border-gray-200">
                <h3 className="font-medium">Активные сессии</h3>
              </CardHeader>
              <CardContent className="p-0">
                {sessionsLoading ? (
                  <div className="p-4">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>IP</TableHead>
                          <TableHead>Браузер</TableHead>
                          <TableHead>Дата создания</TableHead>
                          <TableHead>Дата окончания</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {Array(3).fill(0).map((_, i) => (
                          <TableRow key={i}>
                            <TableCell><Skeleton className="h-4 w-24" /></TableCell>
                            <TableCell><Skeleton className="h-4 w-48" /></TableCell>
                            <TableCell><Skeleton className="h-4 w-32" /></TableCell>
                            <TableCell><Skeleton className="h-4 w-32" /></TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                ) : !userSessions || userSessions.length === 0 ? (
                  <div className="flex flex-col items-center justify-center p-6 text-center">
                    <span className="material-icons text-neutral-gray text-4xl mb-4">
                      devices
                    </span>
                    <p className="text-neutral-gray">Активные сессии не найдены</p>
                  </div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-neutral-light">
                        <TableHead>IP</TableHead>
                        <TableHead>Браузер</TableHead>
                        <TableHead>Дата создания</TableHead>
                        <TableHead>Дата окончания</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {userSessions.map((session: Session) => (
                        <TableRow key={session.id}>
                          <TableCell>{session.ipAddress || "—"}</TableCell>
                          <TableCell>{session.userAgent || "—"}</TableCell>
                          <TableCell>{formatDate(session.createdAt)}</TableCell>
                          <TableCell>{formatDate(session.expiresAt)}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}