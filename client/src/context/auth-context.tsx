import { createContext, useContext, useState, useEffect, ReactNode } from "react";
import { useLocation } from "wouter";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export interface User {
  id: number;
  telegramId: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  avatarUrl?: string;
  isAdmin: boolean;
}

interface AuthContextProps {
  user: User | null;
  loading: boolean;
  isAuthenticated: boolean;
  telegramId: string | null;
  sessionToken: string | null;
  login: (telegramData: any) => Promise<void>;
  verify2FA: (telegramId: string, code: string) => Promise<boolean>;
  resend2FACode: (telegramId: string) => Promise<boolean>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextProps>({
  user: null,
  loading: true,
  isAuthenticated: false,
  telegramId: null,
  sessionToken: null,
  login: async () => {},
  verify2FA: async () => false,
  resend2FACode: async () => false,
  logout: async () => {},
});

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [telegramId, setTelegramId] = useState<string | null>(null);
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
        sessionToken,
        login,
        verify2FA,
        resend2FACode,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};
