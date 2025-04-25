import { createContext, useContext, useState, ReactNode } from "react";

type Language = "en" | "ru";

interface LanguageContextProps {
  language: Language;
  setLanguage: (lang: Language) => void;
  t: (key: string) => string;
}

const LanguageContext = createContext<LanguageContextProps | undefined>(undefined);

// Словари для перевода
const translations: Record<Language, Record<string, string>> = {
  en: {
    // Главная страница
    "signin.title": "Sign in to Telegram",
    "signin.subtitle": "Please confirm your country code",
    "signin.phone": "and enter your phone number.",
    "signin.country": "Country",
    "signin.keep_signed": "Keep me signed in",
    "signin.next": "NEXT",
    "signin.qr": "LOG IN BY QR CODE",
    "signin.continue_ru": "ПРОДОЛЖИТЬ НА РУССКОМ",
    "signin.continue_en": "CONTINUE IN ENGLISH",
    
    // QR-код
    "qr.title": "Log in to Telegram by QR Code",
    "qr.step1": "Open Telegram on your phone",
    "qr.step2": "Go to Settings > Devices > Link Desktop Device",
    "qr.step3": "Point your phone at this screen to scan the QR code",
    "qr.generating": "Generating QR Code...",
    "qr.expires": "QR code expires in {0} seconds",
    "qr.login_phone": "Log in by phone number",
  },
  ru: {
    // Главная страница
    "signin.title": "Вход в Telegram",
    "signin.subtitle": "Пожалуйста, подтвердите код страны",
    "signin.phone": "и введите номер телефона.",
    "signin.country": "Страна",
    "signin.keep_signed": "Оставаться в системе",
    "signin.next": "ДАЛЕЕ",
    "signin.qr": "ВОЙТИ ПО QR-КОДУ",
    "signin.continue_ru": "ПРОДОЛЖИТЬ НА РУССКОМ",
    "signin.continue_en": "CONTINUE IN ENGLISH",
    
    // QR-код
    "qr.title": "Вход в Telegram по QR-коду",
    "qr.step1": "Откройте Telegram на телефоне",
    "qr.step2": "Перейдите в Настройки > Устройства > Подключить устройство",
    "qr.step3": "Наведите камеру телефона на этот экран для сканирования QR-кода",
    "qr.generating": "Генерация QR-кода...",
    "qr.expires": "Срок действия QR-кода истекает через {0} секунд",
    "qr.login_phone": "Войти по номеру телефона",
  }
};

interface LanguageProviderProps {
  children: ReactNode;
}

export function LanguageProvider({ children }: LanguageProviderProps) {
  const [language, setLanguage] = useState<Language>("en");
  
  const t = (key: string): string => {
    const translation = translations[language][key];
    return translation || key;
  };
  
  return (
    <LanguageContext.Provider value={{ language, setLanguage, t }}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage() {
  const context = useContext(LanguageContext);
  if (context === undefined) {
    throw new Error("useLanguage must be used within a LanguageProvider");
  }
  return context;
}