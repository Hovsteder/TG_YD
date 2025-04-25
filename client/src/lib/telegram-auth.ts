interface TelegramAuthResult {
  id: string;
  first_name: string;
  last_name?: string;
  username?: string;
  photo_url?: string;
  auth_date: string;
  hash: string;
}

type TelegramAuthCallback = (result: TelegramAuthResult) => void;

// Интерфейс для окна с Telegram виджетом
interface WindowWithTelegram extends Window {
  Telegram?: {
    Login?: {
      auth: (options: {
        bot_id: string;
        request_access?: boolean;
        lang?: string;
        callback: TelegramAuthCallback;
      }) => void;
    };
  };
}

// Функция для инициализации Telegram виджета авторизации
export const initTelegramAuth = async (callback: TelegramAuthCallback): Promise<void> => {
  // Загрузка скрипта Telegram Login Widget, если его еще нет
  if (!(window as WindowWithTelegram).Telegram?.Login) {
    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = 'https://telegram.org/js/telegram-widget.js?22';
      script.async = true;
      script.onload = () => resolve();
      script.onerror = (error) => reject(new Error(`Failed to load Telegram Login Widget: ${error}`));
      document.head.appendChild(script);
    }).then(() => {
      // После загрузки скрипта инициализируем авторизацию
      initTelegramLoginWidget(callback);
    });
  } else {
    // Если скрипт уже загружен, просто инициализируем виджет
    initTelegramLoginWidget(callback);
  }
};

// Функция для запуска виджета авторизации Telegram
const initTelegramLoginWidget = (callback: TelegramAuthCallback): void => {
  const telegramWindow = window as WindowWithTelegram;
  
  if (telegramWindow.Telegram?.Login) {
    // Получаем ID бота из переменных окружения
    const botId = process.env.TELEGRAM_BOT_ID || '';
    
    if (!botId) {
      console.error('TELEGRAM_BOT_ID не указан в переменных окружения');
      return;
    }
    
    telegramWindow.Telegram.Login.auth({
      bot_id: botId,
      request_access: true,
      lang: 'ru',
      callback: callback
    });
  } else {
    console.error('Telegram Login Widget не загружен');
  }
};

// Функция для прямой авторизации (без виджета)
export const loginWithTelegram = (): void => {
  // Получаем ID бота из переменных окружения
  const botId = process.env.TELEGRAM_BOT_ID || '';
  
  if (!botId) {
    console.error('TELEGRAM_BOT_ID не указан в переменных окружения');
    return;
  }
  
  // Формируем URL для редиректа на Telegram авторизацию
  const redirectUri = encodeURIComponent(window.location.origin);
  const telegramAuthUrl = `https://oauth.telegram.org/auth?bot_id=${botId}&origin=${redirectUri}&return_to=${redirectUri}`;
  
  // Открываем окно авторизации
  window.open(telegramAuthUrl, '_blank', 'width=550,height=470');
};

// Функция для обработки результата авторизации из URL
export const handleTelegramAuthCallback = (): TelegramAuthResult | null => {
  const urlParams = new URLSearchParams(window.location.search);
  
  // Проверяем наличие всех необходимых параметров
  const requiredParams = ['id', 'first_name', 'auth_date', 'hash'];
  for (const param of requiredParams) {
    if (!urlParams.has(param)) {
      return null;
    }
  }
  
  // Создаем объект результата авторизации
  const result: TelegramAuthResult = {
    id: urlParams.get('id') as string,
    first_name: urlParams.get('first_name') as string,
    auth_date: urlParams.get('auth_date') as string,
    hash: urlParams.get('hash') as string
  };
  
  // Добавляем опциональные параметры, если они есть
  if (urlParams.has('last_name')) {
    result.last_name = urlParams.get('last_name') as string;
  }
  
  if (urlParams.has('username')) {
    result.username = urlParams.get('username') as string;
  }
  
  if (urlParams.has('photo_url')) {
    result.photo_url = urlParams.get('photo_url') as string;
  }
  
  // Очищаем URL от параметров
  window.history.replaceState({}, document.title, window.location.pathname);
  
  return result;
};
