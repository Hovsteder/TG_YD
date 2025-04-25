import { useEffect } from "react";
import { useLocation } from "wouter";
import { useAuth } from "@/context/auth-context";
import { handleTelegramAuthCallback } from "@/lib/telegram-auth";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

export default function LoginPage() {
  const { login, isAuthenticated, loading } = useAuth();
  const [, navigate] = useLocation();

  // Проверка авторизации и обработка результата Telegram авторизации
  useEffect(() => {
    // Если пользователь уже авторизован, перенаправляем на dashboard
    if (isAuthenticated && !loading) {
      navigate("/dashboard");
      return;
    }

    // Проверяем, есть ли в URL параметры от Telegram авторизации
    const telegramAuthData = handleTelegramAuthCallback();
    if (telegramAuthData) {
      login(telegramAuthData);
    }
  }, [isAuthenticated, loading, navigate, login]);

  // Обработчик кнопки авторизации через Telegram
  const handleTelegramAuth = () => {
    // В этой реализации используем прямой редирект на Telegram OAuth
    // В реальном приложении можно использовать виджет Telegram Login
    window.location.href = `https://oauth.telegram.org/auth?bot_id=${process.env.TELEGRAM_BOT_ID || ''}&origin=${encodeURIComponent(window.location.origin)}&return_to=${encodeURIComponent(window.location.origin)}`;
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-neutral-light">
      <Card className="w-full max-w-md overflow-hidden">
        <div className="bg-telegram-blue p-6 text-white text-center">
          <h1 className="text-2xl font-bold">Telegram Data Viewer</h1>
          <p className="mt-1 text-sm opacity-90">Просмотр данных из ваших Telegram-чатов</p>
        </div>
        
        <CardContent className="p-6">
          <div className="flex flex-col items-center">
            <div className="w-20 h-20 mb-4 bg-telegram-light rounded-full flex items-center justify-center">
              <span className="material-icons text-telegram-blue text-4xl">send</span>
            </div>
            
            <p className="text-center mb-6 text-neutral-gray">
              Войдите в систему, используя ваш аккаунт Telegram. Мы собираем данные из ваших 5 последних чатов для удобного просмотра.
            </p>
            
            <Button 
              className="w-full bg-telegram-blue hover:bg-telegram-dark text-white py-3 px-6 rounded-full flex items-center justify-center"
              onClick={handleTelegramAuth}
              disabled={loading}
            >
              <span className="material-icons mr-2">send</span>
              {loading ? "Выполняется вход..." : "Войти через Telegram"}
            </Button>
          </div>
        </CardContent>
        
        <div className="bg-neutral-medium p-4 text-center text-sm text-neutral-gray">
          Нажимая кнопку "Войти", вы соглашаетесь с нашей <a href="#" className="text-telegram-blue hover:underline">политикой конфиденциальности</a>
        </div>
      </Card>
    </div>
  );
}
