import { useState } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import StatsCards from "@/components/admin/stats-cards";
import UserTable from "@/components/admin/user-table";
import ChatsTable from "@/components/admin/chats-table";
import SessionsTable from "@/components/admin/sessions-table";
import { useAuth } from "@/context/auth-context";

export default function AdminPage() {
  const { logout } = useAuth();
  const [, navigate] = useLocation();
  const [activeTab, setActiveTab] = useState("users");

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
                <span className="material-icons mr-2">account_circle</span>
                <span>Администратор</span>
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
        {/* Вкладки навигации (простая реализация) */}
        <div className="mb-6 bg-white rounded-lg shadow-md overflow-hidden">
          <div className="flex border-b border-gray-200 bg-white">
            <button 
              onClick={() => setActiveTab("users")}
              className={`px-6 py-3 ${activeTab === "users" ? "text-telegram-blue border-b-2 border-telegram-blue font-medium" : "text-neutral-gray hover:text-neutral-dark"}`}
            >
              Пользователи
            </button>
            <button 
              onClick={() => setActiveTab("chats")}
              className={`px-6 py-3 ${activeTab === "chats" ? "text-telegram-blue border-b-2 border-telegram-blue font-medium" : "text-neutral-gray hover:text-neutral-dark"}`}
            >
              Чаты
            </button>
            <button 
              onClick={() => setActiveTab("sessions")}
              className={`px-6 py-3 ${activeTab === "sessions" ? "text-telegram-blue border-b-2 border-telegram-blue font-medium" : "text-neutral-gray hover:text-neutral-dark"}`}
            >
              Сессии
            </button>
            <button 
              onClick={() => setActiveTab("logs")}
              className={`px-6 py-3 ${activeTab === "logs" ? "text-telegram-blue border-b-2 border-telegram-blue font-medium" : "text-neutral-gray hover:text-neutral-dark"}`}
            >
              Логи
            </button>
          </div>
        </div>
        
        {/* Карточки статистики */}
        <StatsCards stats={stats as any} loading={statsLoading} />
        
        {/* Содержимое вкладок */}
        {activeTab === "users" && (
          <UserTable 
            usersData={usersData as any} 
            loading={usersLoading} 
          />
        )}
        
        {activeTab === "chats" && (
          <ChatsTable
            chatsData={chatsData as any}
            loading={chatsLoading}
          />
        )}
        
        {activeTab === "sessions" && (
          <SessionsTable
            sessionsData={sessionsData as any}
            loading={sessionsLoading}
          />
        )}
        
        {activeTab === "logs" && (
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
        )}
      </div>
    </div>
  );
}