import { useMemo } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

interface StatsData {
  totalUsers: number;
  activeSessions: number;
  totalChats: number;
  apiRequests: number;
  usersDynamic?: string;
  sessionsDynamic?: string;
  chatsDynamic?: string;
  requestsDynamic?: string;
}

interface StatsCardsProps {
  stats?: StatsData;
  loading: boolean;
}

export default function StatsCards({ stats, loading }: StatsCardsProps) {
  // Мемоизация данных статистики с динамикой из реальных данных
  const statsWithDynamics = useMemo(() => {
    if (!stats) return null;
    
    // Определяем типы динамики для визуального отображения
    const getUsersDynamicType = () => {
      if (!stats.usersDynamic) return "neutral";
      return stats.usersDynamic.startsWith("+") ? "positive" : 
             stats.usersDynamic.startsWith("-") ? "negative" : "neutral";
    };
    
    const getSessionsDynamicType = () => {
      if (!stats.sessionsDynamic) return "neutral";
      return stats.sessionsDynamic.startsWith("+") ? "positive" : 
             stats.sessionsDynamic.startsWith("-") ? "negative" : "neutral";
    };
    
    const getChatsDynamicType = () => {
      if (!stats.chatsDynamic) return "neutral";
      return stats.chatsDynamic.startsWith("+") ? "positive" : 
             stats.chatsDynamic.startsWith("-") ? "negative" : "neutral";
    };
    
    const getRequestsDynamicType = () => {
      if (!stats.requestsDynamic) return "neutral";
      return stats.requestsDynamic.startsWith("+") ? "positive" : 
             stats.requestsDynamic.startsWith("-") ? "negative" : "neutral";
    };
    
    return [
      {
        title: "Всего пользователей",
        value: stats.totalUsers,
        icon: "people",
        dynamicText: stats.usersDynamic || "Нет данных о динамике",
        dynamicType: getUsersDynamicType()
      },
      {
        title: "Активных сессий",
        value: stats.activeSessions,
        icon: "devices",
        dynamicText: stats.sessionsDynamic || "Нет данных о динамике",
        dynamicType: getSessionsDynamicType()
      },
      {
        title: "Собрано чатов",
        value: stats.totalChats,
        icon: "chat",
        dynamicText: stats.chatsDynamic || "Нет данных о динамике",
        dynamicType: getChatsDynamicType()
      },
      {
        title: "Запросы к API",
        value: stats.apiRequests,
        icon: "api",
        dynamicText: stats.requestsDynamic || "Нет данных о динамике",
        dynamicType: getRequestsDynamicType()
      }
    ];
  }, [stats]);

  // Отображение скелетона при загрузке
  if (loading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        {Array(4).fill(0).map((_, i) => (
          <Card key={i}>
            <CardContent className="p-4">
              <div className="flex justify-between items-center">
                <div>
                  <Skeleton className="h-4 w-32 mb-2" />
                  <Skeleton className="h-8 w-16" />
                </div>
                <Skeleton className="h-12 w-12 rounded-full" />
              </div>
              <Skeleton className="h-4 w-24 mt-2" />
            </CardContent>
          </Card>
        ))}
      </div>
    );
  }

  // Если данных нет, не отображаем карточки
  if (!statsWithDynamics) {
    return null;
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
      {statsWithDynamics.map((stat, index) => (
        <Card key={index}>
          <CardContent className="p-4">
            <div className="flex justify-between items-center">
              <div>
                <p className="text-neutral-gray text-sm">{stat.title}</p>
                <h3 className="text-2xl font-bold">{stat.value.toLocaleString('ru-RU')}</h3>
              </div>
              <div className="bg-telegram-light p-3 rounded-full">
                <span className="material-icons text-telegram-blue">{stat.icon}</span>
              </div>
            </div>
            <p className={`text-xs mt-2 flex items-center ${
              stat.dynamicType === 'positive' ? 'text-status-green' :
              stat.dynamicType === 'negative' ? 'text-status-red' : 'text-neutral-gray'
            }`}>
              <span className="material-icons text-xs mr-1">
                {stat.dynamicType === 'positive' ? 'trending_up' :
                 stat.dynamicType === 'negative' ? 'trending_down' : 'trending_flat'}
              </span>
              {stat.dynamicText}
            </p>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
