import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useQuery, useQueryClient } from "@tanstack/react-query";

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
  const [loading, setLoading] = useState(false);
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
    meta: { headers },
    onSuccess: (data) => {
      // Находим настройку для токена бота
      const botTokenSetting = data.find(s => s.key === "telegram_bot_token");
      if (botTokenSetting) {
        setTelegramBotToken(botTokenSetting.value);
      }
    }
  });

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
        {
          headers: {
            "Admin-Authorization": adminToken || ""
          }
        }
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

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-xl font-medium mb-4">Настройки системы</h2>
      
      {settingsLoading ? (
        <p className="text-neutral-gray">Загрузка настроек...</p>
      ) : (
        <div className="space-y-6">
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
          
          {/* Другие настройки системы можно добавить здесь */}
        </div>
      )}
    </div>
  );
}