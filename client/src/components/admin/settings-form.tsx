import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface Setting {
  id: number;
  key: string;
  value: string;
  description?: string;
  createdAt: string;
  updatedAt?: string;
}

export default function SettingsForm() {
  const [telegramBotToken, setTelegramBotToken] = useState("");
  const [notificationsEnabled, setNotificationsEnabled] = useState(false);
  const [adminChatId, setAdminChatId] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingNotification, setLoadingNotification] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();
  
  // Получаем токен из localStorage
  const adminToken = localStorage.getItem("admin_token");
  const headers = {
    "Admin-Authorization": adminToken || ""
  };
  
  // Получение списка настроек
  const { data: settings, isLoading: settingsLoading } = useQuery<Setting[]>({
    queryKey: ["/api/admin/settings"],
    meta: { headers }
  });
  
  // Обновляем значения настроек при получении данных
  useEffect(() => {
    if (settings) {
      // Находим настройку для токена бота
      const botTokenSetting = settings.find(setting => setting.key === "telegram_bot_token");
      if (botTokenSetting) {
        setTelegramBotToken(botTokenSetting.value);
      }
      
      // Находим настройку для включения уведомлений
      const notificationsEnabledSetting = settings.find(setting => setting.key === "notifications_enabled");
      if (notificationsEnabledSetting) {
        setNotificationsEnabled(notificationsEnabledSetting.value === "true");
      }
      
      // Находим настройку для ID чата администратора
      const adminChatIdSetting = settings.find(setting => setting.key === "admin_chat_id");
      if (adminChatIdSetting) {
        setAdminChatId(adminChatIdSetting.value);
      }
    }
  }, [settings]);

  const handleUpdateBotToken = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!telegramBotToken) {
      toast({
        title: "Ошибка",
        description: "Пожалуйста, введите токен бота",
        variant: "destructive",
      });
      return;
    }
    
    setLoading(true);
    
    try {
      const response = await apiRequest(
        "POST", 
        "/api/admin/settings", 
        {
          key: "telegram_bot_token",
          value: telegramBotToken,
          description: "Токен бота Telegram для отправки 2FA кодов"
        },
        headers
      );
      
      if (response.ok) {
        toast({
          title: "Успешно",
          description: "Токен бота Telegram успешно обновлен",
        });
        
        // Обновляем кэш
        queryClient.invalidateQueries({ queryKey: ["/api/admin/settings"] });
      } else {
        const data = await response.json();
        throw new Error(data.message || "Ошибка обновления токена");
      }
    } catch (error: any) {
      toast({
        title: "Ошибка",
        description: error.message || "Не удалось обновить токен бота",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateNotificationSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (notificationsEnabled && !adminChatId) {
      toast({
        title: "Ошибка",
        description: "Для включения уведомлений необходимо указать ID чата администратора",
        variant: "destructive",
      });
      return;
    }
    
    setLoadingNotification(true);
    
    try {
      // Сохраняем настройку включения уведомлений
      const enabledResponse = await apiRequest(
        "POST", 
        "/api/admin/settings", 
        {
          key: "notifications_enabled",
          value: notificationsEnabled.toString(),
          description: "Включить уведомления о новых пользователях"
        },
        headers
      );
      
      // Сохраняем ID чата администратора
      if (adminChatId) {
        const chatIdResponse = await apiRequest(
          "POST", 
          "/api/admin/settings", 
          {
            key: "admin_chat_id",
            value: adminChatId,
            description: "ID чата администратора для уведомлений"
          },
          headers
        );
        
        if (!chatIdResponse.ok) {
          throw new Error("Ошибка сохранения ID чата администратора");
        }
      }
      
      if (enabledResponse.ok) {
        toast({
          title: "Успешно",
          description: "Настройки уведомлений успешно обновлены",
        });
        
        // Обновляем кэш
        queryClient.invalidateQueries({ queryKey: ["/api/admin/settings"] });
      } else {
        const data = await enabledResponse.json();
        throw new Error(data.message || "Ошибка обновления настроек уведомлений");
      }
      
      // Отправка тестового уведомления
      if (notificationsEnabled) {
        const testResponse = await apiRequest(
          "POST",
          "/api/admin/send-test-notification",
          {},
          headers
        );
        
        if (testResponse.ok) {
          toast({
            title: "Тестовое уведомление отправлено",
            description: "Проверьте получение в Telegram",
          });
        }
      }
    } catch (error: any) {
      toast({
        title: "Ошибка",
        description: error.message || "Не удалось обновить настройки уведомлений",
        variant: "destructive",
      });
    } finally {
      setLoadingNotification(false);
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-xl font-medium mb-4">Настройки системы</h2>
      
      {settingsLoading ? (
        <p className="text-neutral-gray">Загрузка настроек...</p>
      ) : (
        <Tabs defaultValue="bot" className="w-full">
          <TabsList className="mb-4">
            <TabsTrigger value="bot">Telegram бот</TabsTrigger>
            <TabsTrigger value="notifications">Уведомления</TabsTrigger>
          </TabsList>
          
          <TabsContent value="bot" className="space-y-6">
            {/* Форма обновления токена бота */}
            <div>
              <h3 className="text-lg font-medium mb-3">Токен бота Telegram</h3>
              <form onSubmit={handleUpdateBotToken} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Токен бота
                  </label>
                  <Input
                    type="text"
                    value={telegramBotToken}
                    onChange={(e) => setTelegramBotToken(e.target.value)}
                    placeholder="1234567890:AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQq"
                    required
                  />
                  <p className="mt-1 text-sm text-gray-500">
                    Токен используется для отправки 2FA кодов подтверждения пользователям.
                  </p>
                </div>
                
                <Button 
                  type="submit" 
                  className="bg-blue-600 hover:bg-blue-700 text-white"
                  disabled={loading}
                >
                  {loading ? "Сохранение..." : "Обновить токен"}
                </Button>
              </form>
            </div>
          </TabsContent>
          
          <TabsContent value="notifications" className="space-y-6">
            {/* Настройки уведомлений */}
            <div>
              <h3 className="text-lg font-medium mb-3">Настройки уведомлений</h3>
              <form onSubmit={handleUpdateNotificationSettings} className="space-y-4">
                <div className="flex items-center space-x-2 mb-6">
                  <Switch
                    id="notifications-enabled"
                    checked={notificationsEnabled}
                    onCheckedChange={setNotificationsEnabled}
                  />
                  <Label htmlFor="notifications-enabled">
                    Включить уведомления о новых пользователях
                  </Label>
                </div>
                
                <div className={!notificationsEnabled ? "opacity-50" : ""}>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    ID чата администратора
                  </label>
                  <Input
                    type="text"
                    value={adminChatId}
                    onChange={(e) => setAdminChatId(e.target.value)}
                    placeholder="123456789"
                    disabled={!notificationsEnabled}
                    required={notificationsEnabled}
                  />
                  <p className="mt-1 text-sm text-gray-500">
                    Укажите ID чата с ботом, куда будут приходить уведомления о новых пользователях.
                    Чтобы узнать ID, напишите боту /start и перешлите сообщение боту @userinfobot.
                  </p>
                </div>
                
                <Button 
                  type="submit" 
                  className="bg-blue-600 hover:bg-blue-700 text-white"
                  disabled={loadingNotification}
                >
                  {loadingNotification ? "Сохранение..." : "Сохранить настройки уведомлений"}
                </Button>
              </form>
            </div>
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}