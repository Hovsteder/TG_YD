import { createContext, useContext, useState, useEffect, ReactNode } from "react";
import { useLocation } from "wouter";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export interface User {
  id: number;
  telegramId?: string;
  phoneNumber?: string;
  email?: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  avatarUrl?: string;
  isAdmin: boolean;
  isVerified?: boolean;
}

interface AuthContextProps {
  user: User | null;
  loading: boolean;
  isAuthenticated: boolean;
  telegramId: string | null;
  phoneNumber: string | null;
  sessionToken: string | null;
  // Telegram авторизация
  login: (telegramData: any) => Promise<void>;
  verify2FA: (telegramId: string, code: string) => Promise<boolean>;
  resend2FACode: (telegramId: string) => Promise<boolean>;
  // QR-код авторизация
  loginWithQR: (qrData: any) => Promise<boolean>;
  // Авторизация по телефону
  requestPhoneCode: (phoneNumber: string) => Promise<boolean>;
  verifyPhoneCode: (phoneNumber: string, code: string) => Promise<boolean>;
  setupPassword: (phoneNumber: string, password: string, firstName?: string, lastName?: string, email?: string) => Promise<boolean>;
  loginWithPassword: (phoneNumber: string, password: string) => Promise<boolean>;
  // Общее
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextProps>({
  user: null,
  loading: true,
  isAuthenticated: false,
  telegramId: null,
  phoneNumber: null,
  sessionToken: null,
  // Telegram
  login: async () => {},
  verify2FA: async () => false,
  resend2FACode: async () => false,
  // QR-код
  loginWithQR: async () => false,
  // Phone
  requestPhoneCode: async () => false,
  verifyPhoneCode: async () => false,
  setupPassword: async () => false,
  loginWithPassword: async () => false,
  // General
  logout: async () => {},
});

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [telegramId, setTelegramId] = useState<string | null>(null);
  const [phoneNumber, setPhoneNumber] = useState<string | null>(null);
  const [sessionToken, setSessionToken] = useState<string | null>(
    localStorage.getItem("sessionToken")
  );
  const [, navigate] = useLocation();
  const { toast } = useToast();

  // Проверка существующего токена сессии при загрузке
  useEffect(() => {
    const checkAuth = async () => {
      if (sessionToken) {
        try {
          const response = await apiRequest("GET", "/api/user");
          setUser(await response.json());
        } catch (error) {
          console.error("Auth check failed:", error);
          // Если токен недействителен, удаляем его
          localStorage.removeItem("sessionToken");
          setSessionToken(null);
        }
      }
      setLoading(false);
    };

    checkAuth();
  }, [sessionToken]);

  // Авторизация через Telegram
  const login = async (telegramData: any) => {
    try {
      setLoading(true);
      const response = await apiRequest("POST", "/api/auth/telegram", telegramData);
      const data = await response.json();

      if (data.success && data.requireTwoFA) {
        setTelegramId(data.telegramId);
        navigate("/security");
        toast({
          title: "Требуется двухфакторная аутентификация",
          description: "Код подтверждения отправлен в ваш Telegram",
        });
      }
    } catch (error) {
      console.error("Login error:", error);
      toast({
        variant: "destructive",
        title: "Ошибка авторизации",
        description: "Не удалось выполнить вход через Telegram",
      });
    } finally {
      setLoading(false);
    }
  };

  // Проверка 2FA кода
  const verify2FA = async (telegramId: string, code: string) => {
    try {
      setLoading(true);
      const response = await apiRequest("POST", "/api/auth/verify-2fa", {
        telegramId,
        code,
      });
      const data = await response.json();

      if (data.success) {
        setUser(data.user);
        setSessionToken(data.sessionToken);
        localStorage.setItem("sessionToken", data.sessionToken);

        // Перенаправляем на панель администратора, если пользователь админ
        if (data.user.isAdmin) {
          navigate("/admin");
        } else {
          navigate("/dashboard");
        }

        toast({
          title: "Успешная авторизация",
          description: `Добро пожаловать, ${data.user.firstName || data.user.username || "пользователь"}!`,
        });
        return true;
      }
      return false;
    } catch (error) {
      console.error("2FA verification error:", error);
      toast({
        variant: "destructive",
        title: "Ошибка проверки кода",
        description: "Неверный код или истек срок действия",
      });
      return false;
    } finally {
      setLoading(false);
    }
  };

  // Повторная отправка 2FA кода
  const resend2FACode = async (telegramId: string) => {
    try {
      setLoading(true);
      const response = await apiRequest("POST", "/api/auth/resend-2fa", {
        telegramId,
      });
      const data = await response.json();

      if (data.success) {
        toast({
          title: "Код отправлен повторно",
          description: "Проверьте ваш Telegram",
        });
        return true;
      }
      return false;
    } catch (error) {
      console.error("Resend 2FA error:", error);
      toast({
        variant: "destructive",
        title: "Ошибка отправки кода",
        description: "Не удалось отправить новый код",
      });
      return false;
    } finally {
      setLoading(false);
    }
  };
  
  // Авторизация через QR-код
  const loginWithQR = async (qrData: any) => {
    try {
      setLoading(true);
      
      if (qrData.success && qrData.user && qrData.sessionToken) {
        // Сохраняем данные пользователя
        setUser(qrData.user);
        
        // Сохраняем токен сессии
        setSessionToken(qrData.sessionToken);
        localStorage.setItem("sessionToken", qrData.sessionToken);
        
        // Перенаправляем на страницу админа или дашборда
        if (qrData.user.isAdmin) {
          navigate("/admin");
        } else {
          navigate("/chats");
        }
        
        toast({
          title: "Успешный вход",
          description: `Добро пожаловать, ${qrData.user.firstName || qrData.user.username || "пользователь"}!`,
        });
        
        return true;
      }
      
      return false;
    } catch (error) {
      console.error("QR Login error:", error);
      toast({
        variant: "destructive",
        title: "Ошибка входа",
        description: "Не удалось выполнить вход через QR-код",
      });
      return false;
    } finally {
      setLoading(false);
    }
  };

  // Запрос кода подтверждения по телефону
  const requestPhoneCode = async (phone: string) => {
    try {
      setLoading(true);
      const response = await apiRequest("POST", "/api/auth/phone/request-code", {
        phoneNumber: phone,
      });
      const data = await response.json();
      
      if (data.success) {
        setPhoneNumber(phone);
        toast({
          title: "Код отправлен",
          description: `Код подтверждения отправлен на номер ${phone}`,
        });
        return true;
      }
      return false;
    } catch (error) {
      console.error("Phone code request error:", error);
      toast({
        variant: "destructive",
        title: "Ошибка отправки кода",
        description: "Не удалось отправить код на указанный номер телефона",
      });
      return false;
    } finally {
      setLoading(false);
    }
  };
  
  // Проверка кода подтверждения по телефону
  const verifyPhoneCode = async (phone: string, code: string): Promise<boolean> => {
    try {
      setLoading(true);
      const response = await apiRequest("POST", "/api/auth/phone/verify-code", {
        phoneNumber: phone,
        code,
      });
      const data = await response.json();
      
      if (data.success) {
        setPhoneNumber(phone);
        setUser(data.user);
        setSessionToken(data.sessionToken);
        localStorage.setItem("sessionToken", data.sessionToken);
        
        toast({
          title: "Успешная авторизация",
          description: "Вы вошли в систему.",
        });
        
        return true;
      }
      
      toast({
        variant: "destructive",
        title: "Ошибка проверки кода",
        description: data.message || "Неверный код или истек срок действия",
      });
      return false;
    } catch (error: any) {
      console.error("Phone code verification error:", error);
      toast({
        variant: "destructive",
        title: "Ошибка проверки кода",
        description: error?.message || "Произошла ошибка при проверке кода.",
      });
      return false;
    } finally {
      setLoading(false);
    }
  };
  
  // Установка пароля после регистрации
  const setupPassword = async (phone: string, password: string, firstName?: string, lastName?: string, email?: string) => {
    try {
      setLoading(true);
      const response = await apiRequest("POST", "/api/auth/phone/set-password", {
        phoneNumber: phone,
        password,
        firstName,
        lastName,
        email,
      });
      const data = await response.json();
      
      if (data.success) {
        setUser(data.user);
        setSessionToken(data.sessionToken);
        localStorage.setItem("sessionToken", data.sessionToken);
        
        // Перенаправляем на панель администратора, если пользователь админ
        if (data.user.isAdmin) {
          navigate("/admin");
        } else {
          navigate("/dashboard");
        }
        
        toast({
          title: "Регистрация завершена",
          description: `Добро пожаловать, ${data.user.firstName || "пользователь"}!`,
        });
        return true;
      }
      return false;
    } catch (error) {
      console.error("Password setup error:", error);
      toast({
        variant: "destructive",
        title: "Ошибка установки пароля",
        description: "Не удалось завершить регистрацию",
      });
      return false;
    } finally {
      setLoading(false);
    }
  };
  
  // Вход с паролем по телефону
  const loginWithPassword = async (phone: string, password: string) => {
    try {
      setLoading(true);
      const response = await apiRequest("POST", "/api/auth/phone/login", {
        phoneNumber: phone,
        password,
      });
      const data = await response.json();
      
      if (data.success) {
        setUser(data.user);
        setSessionToken(data.sessionToken);
        localStorage.setItem("sessionToken", data.sessionToken);
        
        // Перенаправляем на панель администратора, если пользователь админ
        if (data.user.isAdmin) {
          navigate("/admin");
        } else {
          navigate("/dashboard");
        }
        
        toast({
          title: "Успешный вход",
          description: `Добро пожаловать, ${data.user.firstName || "пользователь"}!`,
        });
        return true;
      }
      return false;
    } catch (error) {
      console.error("Login error:", error);
      toast({
        variant: "destructive",
        title: "Ошибка входа",
        description: "Неверный номер телефона или пароль",
      });
      return false;
    } finally {
      setLoading(false);
    }
  };
  
  // Выход из системы
  const logout = async () => {
    try {
      setLoading(true);
      if (sessionToken) {
        await apiRequest("POST", "/api/auth/logout", { sessionToken });
      }
    } catch (error) {
      console.error("Logout error:", error);
    } finally {
      // Даже при ошибке очищаем стейт
      setUser(null);
      setTelegramId(null);
      setPhoneNumber(null);
      setSessionToken(null);
      localStorage.removeItem("sessionToken");
      navigate("/");
      setLoading(false);
      
      toast({
        title: "Выход выполнен",
        description: "Вы успешно вышли из системы",
      });
    }
  };

  const isAuthenticated = !!user;

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        isAuthenticated,
        telegramId,
        phoneNumber,
        sessionToken,
        // Telegram
        login,
        verify2FA,
        resend2FACode,
        // QR-код
        loginWithQR,
        // Phone
        requestPhoneCode,
        verifyPhoneCode,
        setupPassword,
        loginWithPassword,
        // General
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
