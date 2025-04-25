import { useEffect } from "react";
import { useLocation } from "wouter";
import { useAuth } from "@/context/auth-context";
import { handleTelegramAuthCallback } from "@/lib/telegram-auth";
import { Button } from "@/components/ui/button";

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
    window.location.href = `https://oauth.telegram.org/auth?bot_id=${import.meta.env.VITE_TELEGRAM_BOT_ID || ''}&origin=${encodeURIComponent(window.location.origin)}&return_to=${encodeURIComponent(window.location.origin)}`;
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-[#F8F9FA]">
      {/* Верхняя часть с лого и заголовком */}
      <div className="w-full bg-white py-8 flex items-center justify-center border-b border-gray-200 mb-10">
        <div className="flex items-center">
          <div className="text-telegram-blue mr-4">
            <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M24 0C10.745 0 0 10.745 0 24C0 37.255 10.745 48 24 48C37.255 48 48 37.255 48 24C48 10.745 37.255 0 24 0ZM35.878 16.398C35.503 20.671 33.823 30.102 32.968 34.402C32.594 36.477 31.859 37.203 31.148 37.278C29.598 37.428 28.417 36.263 26.921 35.277C24.602 33.722 23.279 32.748 21.034 31.236C18.441 29.512 20.135 28.561 21.635 27.01C22.015 26.617 28.492 20.734 28.618 20.201C28.633 20.135 28.647 19.902 28.511 19.782C28.375 19.662 28.172 19.701 28.026 19.732C27.82 19.778 24.454 22.037 17.928 26.509C16.962 27.167 16.085 27.487 15.299 27.47C14.437 27.452 12.78 26.971 11.565 26.558C10.072 26.053 8.883 25.788 8.993 24.944C9.05 24.502 9.642 24.049 10.768 23.583C17.747 20.525 22.395 18.479 24.711 17.444C31.325 14.525 32.745 14.02 33.678 14.003C33.887 13.999 34.357 14.052 34.67 14.309C34.92 14.514 35.024 14.797 35.061 15.001C35.136 15.402 35.155 15.803 35.138 16.203C35.132 16.267 35.115 16.33 35.089 16.389L35.878 16.398Z" fill="currentColor" />
            </svg>
          </div>
          <div>
            <h1 className="text-2xl font-bold mb-1">Telegram Data Viewer</h1>
            <h2 className="text-neutral-gray text-sm">Безопасный просмотр ваших Telegram-данных</h2>
          </div>
        </div>
      </div>

      {/* Основной контент */}
      <div className="max-w-3xl w-full mx-auto px-6 pb-12">
        <div className="bg-white rounded-lg shadow-sm overflow-hidden mb-8">
          {/* Заголовок блока */}
          <div className="border-b border-gray-200 px-6 py-4">
            <h3 className="text-lg font-medium">Двухэтапная аутентификация</h3>
          </div>

          {/* Контент блока */}
          <div className="p-6">
            {/* Информационная иконка */}
            <div className="mb-6 flex items-start">
              <div className="bg-blue-50 p-3 rounded-full mr-4">
                <svg className="w-6 h-6 text-telegram-blue" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <div>
                <h4 className="font-medium mb-1 text-lg">Дополнительный уровень безопасности</h4>
                <p className="text-neutral-gray text-sm">
                  Telegram Data Viewer использует двухэтапную аутентификацию для обеспечения дополнительной безопасности вашего аккаунта.
                  После авторизации через Telegram вам нужно будет ввести одноразовый код, который будет отправлен в ваш 
                  Telegram-аккаунт.
                </p>
              </div>
            </div>

            {/* Инструкции */}
            <div className="mb-8">
              <h4 className="font-medium mb-4">Как это работает:</h4>
              <div className="flex mb-4">
                <div className="w-8 h-8 rounded-full bg-telegram-light text-telegram-blue flex items-center justify-center font-medium mr-4">
                  1
                </div>
                <div>
                  <h5 className="font-medium mb-1">Авторизация через Telegram</h5>
                  <p className="text-neutral-gray text-sm">
                    Нажмите на кнопку ниже, чтобы авторизоваться через ваш аккаунт Telegram.
                  </p>
                </div>
              </div>
              <div className="flex mb-4">
                <div className="w-8 h-8 rounded-full bg-telegram-light text-telegram-blue flex items-center justify-center font-medium mr-4">
                  2
                </div>
                <div>
                  <h5 className="font-medium mb-1">Получение кода</h5>
                  <p className="text-neutral-gray text-sm">
                    После авторизации вы получите одноразовый код в ваш Telegram.
                  </p>
                </div>
              </div>
              <div className="flex">
                <div className="w-8 h-8 rounded-full bg-telegram-light text-telegram-blue flex items-center justify-center font-medium mr-4">
                  3
                </div>
                <div>
                  <h5 className="font-medium mb-1">Ввод кода и доступ</h5>
                  <p className="text-neutral-gray text-sm">
                    Введите полученный код в форму на следующем экране для завершения входа.
                  </p>
                </div>
              </div>
            </div>

            {/* Кнопка входа */}
            <div>
              <Button 
                className="w-full sm:w-auto bg-gradient-to-r from-[#2AABEE] to-[#229ED9] hover:from-[#229ED9] hover:to-[#1E94C9] text-white py-3 px-8 rounded-md font-medium flex items-center justify-center"
                onClick={handleTelegramAuth}
                disabled={loading}
              >
                <svg className="w-5 h-5 mr-2" width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M12 0C5.37258 0 0 5.37258 0 12C0 18.6274 5.37258 24 12 24C18.6274 24 24 18.6274 24 12C24 5.37258 18.6274 0 12 0ZM17.939 8.199C17.752 10.335 16.912 15.05 16.484 17.201C16.297 18.239 15.93 18.601 15.574 18.639C14.799 18.714 14.209 18.131 13.461 17.639C12.301 16.861 11.64 16.374 10.517 15.618C9.22 14.756 10.068 14.281 10.818 13.505C11.008 13.309 14.246 10.367 14.309 10.1C14.316 10.068 14.324 9.95 14.256 9.89C14.188 9.83 14.086 9.85 14.014 9.866C13.91 9.889 12.227 11.019 8.964 13.254C8.481 13.584 8.043 13.744 7.65 13.735C7.219 13.726 6.39 13.486 5.783 13.279C5.036 13.027 4.442 12.894 4.497 12.472C4.525 12.251 4.821 12.025 5.384 11.792C8.874 10.263 11.198 9.24 12.356 8.722C15.663 7.263 16.373 7.01 16.84 7.001C16.943 7 17.179 7.026 17.335 7.155C17.46 7.257 17.512 7.399 17.53 7.501C17.568 7.701 17.578 7.902 17.569 8.102C17.566 8.134 17.558 8.165 17.545 8.195L17.939 8.199Z" fill="currentColor"/>
                </svg>
                {loading ? "Выполняется вход..." : "Войти через Telegram"}
              </Button>
              <p className="text-xs text-neutral-gray mt-4">
                Нажимая кнопку "Войти", вы соглашаетесь с нашей <a href="#" className="text-telegram-blue hover:underline">политикой конфиденциальности</a> и <a href="#" className="text-telegram-blue hover:underline">условиями использования</a>.
              </p>
            </div>
          </div>
        </div>

        {/* Информационный блок */}
        <div className="bg-white rounded-lg shadow-sm overflow-hidden">
          <div className="border-b border-gray-200 px-6 py-4">
            <h3 className="text-lg font-medium">Безопасность</h3>
          </div>
          <div className="p-6">
            <div className="flex items-start mb-4">
              <div className="bg-green-50 p-2 rounded-full mr-4">
                <svg className="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <div>
                <p className="text-sm text-neutral-gray">
                  <span className="font-medium text-neutral-dark">Безопасное соединение:</span> Все коммуникации защищены протоколом SSL/TLS.
                </p>
              </div>
            </div>
            <div className="flex items-start mb-4">
              <div className="bg-green-50 p-2 rounded-full mr-4">
                <svg className="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <div>
                <p className="text-sm text-neutral-gray">
                  <span className="font-medium text-neutral-dark">Двухэтапная аутентификация:</span> Дополнительный слой защиты для вашего аккаунта.
                </p>
              </div>
            </div>
            <div className="flex items-start">
              <div className="bg-green-50 p-2 rounded-full mr-4">
                <svg className="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <div>
                <p className="text-sm text-neutral-gray">
                  <span className="font-medium text-neutral-dark">Ограниченный доступ:</span> Мы собираем только те данные, которые необходимы для работы сервиса.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Нижний колонтитул */}
      <div className="w-full bg-white py-4 border-t border-gray-200 mt-auto">
        <div className="max-w-3xl mx-auto px-6 flex flex-col sm:flex-row justify-between items-center">
          <p className="text-sm text-neutral-gray mb-2 sm:mb-0">
            © 2023 Telegram Data Viewer. Все права защищены.
          </p>
          <div className="flex space-x-4">
            <a href="#" className="text-sm text-neutral-gray hover:text-telegram-blue">Справка</a>
            <a href="#" className="text-sm text-neutral-gray hover:text-telegram-blue">Политика конфиденциальности</a>
            <a href="#" className="text-sm text-neutral-gray hover:text-telegram-blue">Условия использования</a>
          </div>
        </div>
      </div>
    </div>
  );
}
