import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/context/auth-context";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import StatsCards from "@/components/admin/stats-cards";
import UserTable from "@/components/admin/user-table";
import ChatsTable from "@/components/admin/chats-table";
import SessionsTable from "@/components/admin/sessions-table";

export default function AdminPage() {
  const { user, isAuthenticated, loading, logout } = useAuth();
  const [, navigate] = useLocation();
  const [activeTab, setActiveTab] = useState("users");

  // Временно отключаем проверку прав администратора для тестирования
  // useEffect(() => {
  //   if (!loading && (!isAuthenticated || !user?.isAdmin)) {
  //     navigate("/");
  //   }
  // }, [isAuthenticated, loading, navigate, user]);

  // Получение статистики (временно убрана проверка прав)
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ["/api/admin/stats"],
    enabled: true,
  });

  // Получение списка пользователей (временно убрана проверка прав)
  const { data: usersData, isLoading: usersLoading } = useQuery({
    queryKey: ["/api/admin/users"],
    enabled: activeTab === "users",
  });

  // Получение списка чатов (временно убрана проверка прав)
  const { data: chatsData, isLoading: chatsLoading } = useQuery({
    queryKey: ["/api/admin/chats"],
    enabled: activeTab === "chats",
  });

  // Получение списка сессий (временно убрана проверка прав)
  const { data: sessionsData, isLoading: sessionsLoading } = useQuery({
    queryKey: ["/api/admin/sessions"],
    enabled: activeTab === "sessions",
  });

  // Получение логов (временно убрана проверка прав)
  const { data: logs, isLoading: logsLoading } = useQuery({
    queryKey: ["/api/admin/logs"],
    enabled: activeTab === "logs",
  });

  // Обработчик для возврата в приложение
  const handleBackToApp = () => {
    navigate("/dashboard");
  };

  // Обработчик смены вкладки
  const handleTabChange = (tab: string) => {
    setActiveTab(tab);
  };

  // Проверяем только загрузку для тестирования
  if (loading) {
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
      {/* Шапка админ-панели */}
      <header className="bg-neutral-dark text-white shadow-md">
        <div className="container mx-auto px-4 py-3 flex justify-between items-center">
          <div className="flex items-center">
            <span className="material-icons mr-2">admin_panel_settings</span>
            <h1 className="font-bold text-xl">Админ-панель</h1>
          </div>
          
          <div className="flex items-center">
            <button 
              className="bg-telegram-blue hover:bg-telegram-dark text-white py-1 px-3 rounded-md flex items-center text-sm"
              onClick={handleBackToApp}
            >
              <span className="material-icons mr-1" style={{ fontSize: "16px" }}>arrow_back</span>
              Вернуться в приложение
            </button>
            <div className="mx-4 h-6 border-l border-gray-500"></div>
            <div className="relative">
              <div className="flex items-center">
                {user.avatarUrl ? (
                  <img 
                    src={user.avatarUrl} 
                    alt="Аватар администратора" 
                    className="w-8 h-8 rounded-full mr-2"
                  />
                ) : (
                  <span className="material-icons mr-2">account_circle</span>
                )}
                <span>{user.firstName || user.username || "Администратор"}</span>
                <button className="ml-3 text-sm" onClick={logout}>
                  <span className="material-icons">logout</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Основной контент */}
      <div className="container mx-auto px-4 py-6">
        {/* Вкладки навигации */}
        <div className="mb-6 bg-white rounded-lg shadow-md overflow-hidden">
          <Tabs value={activeTab} onValueChange={handleTabChange}>
            <TabsList className="flex border-b border-gray-200 bg-white">
              <TabsTrigger 
                value="users" 
                className="px-6 py-3 data-[state=active]:text-telegram-blue data-[state=active]:border-b-2 data-[state=active]:border-telegram-blue font-medium"
              >
                Пользователи
              </TabsTrigger>
              <TabsTrigger 
                value="chats" 
                className="px-6 py-3 data-[state=inactive]:text-neutral-gray data-[state=inactive]:hover:text-neutral-dark"
              >
                Чаты
              </TabsTrigger>
              <TabsTrigger 
                value="sessions" 
                className="px-6 py-3 data-[state=inactive]:text-neutral-gray data-[state=inactive]:hover:text-neutral-dark"
              >
                Сессии
              </TabsTrigger>
              <TabsTrigger 
                value="logs" 
                className="px-6 py-3 data-[state=inactive]:text-neutral-gray data-[state=inactive]:hover:text-neutral-dark"
              >
                Логи
              </TabsTrigger>
            </TabsList>
          </Tabs>
        </div>
        
        {/* Карточки статистики */}
        <StatsCards stats={stats as any} loading={statsLoading} />
        
        {/* Содержимое вкладок */}
        <TabsContent value="users" className="mt-0">
          <UserTable 
            usersData={usersData as any} 
            loading={usersLoading} 
          />
        </TabsContent>
        
        <TabsContent value="chats" className="mt-0">
          <ChatsTable
            chatsData={chatsData as any}
            loading={chatsLoading}
          />
        </TabsContent>
        
        <TabsContent value="sessions" className="mt-0">
          <SessionsTable
            sessionsData={sessionsData as any}
            loading={sessionsLoading}
          />
        </TabsContent>
        
        <TabsContent value="logs" className="mt-0">
          <div className="bg-white rounded-lg shadow-md p-6">
            <h2 className="text-xl font-medium mb-4">Логи системы</h2>
            {logsLoading ? (
              <p className="text-neutral-gray">Загрузка логов...</p>
            ) : logs && Array.isArray(logs) && logs.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="min-w-full">
                  <thead>
                    <tr className="bg-neutral-light border-b border-gray-200">
                      <th className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">ID</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">Пользователь</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">Действие</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">IP-адрес</th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">Дата и время</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {logs.map((log: any) => (
                      <tr key={log.id} className="hover:bg-neutral-light">
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-dark">{log.id}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-dark">{log.userId || 'Система'}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-dark">{log.action}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-gray">{log.ipAddress || '-'}</td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-neutral-gray">
                          {new Date(log.timestamp).toLocaleString('ru-RU')}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-neutral-gray">Логи отсутствуют</p>
            )}
          </div>
        </TabsContent>
      </div>
    </div>
  );
}
