import { useState } from "react";
import { useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

export default function AdminLoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [, navigate] = useLocation();
  const { toast } = useToast();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!username || !password) {
      toast({
        title: "Ошибка",
        description: "Пожалуйста, введите имя пользователя и пароль",
        variant: "destructive",
      });
      return;
    }

    setLoading(true);

    try {
      const response = await apiRequest("POST", "/api/auth/admin-login", {
        username,
        password,
      });

      const data = await response.json();

      if (response.ok) {
        // Сохраняем данные администратора в localStorage
        localStorage.setItem("admin_token", data.sessionToken);
        localStorage.setItem("admin_user", JSON.stringify(data.user));

        toast({
          title: "Успешно",
          description: "Вы вошли в панель администратора",
        });

        navigate("/admin");
      } else {
        throw new Error(data.message || "Ошибка авторизации");
      }
    } catch (error: any) {
      toast({
        title: "Ошибка",
        description: error.message || "Не удалось войти в систему",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="bg-white p-8 rounded-lg shadow-md w-full max-w-md">
        <div className="mb-8 text-center">
          <h1 className="text-2xl font-bold mb-2">Вход в панель администратора</h1>
          <p className="text-gray-500 text-sm">
            Введите имя пользователя и пароль для доступа к панели управления
          </p>
        </div>

        <form onSubmit={handleLogin}>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1" htmlFor="username">
                Имя пользователя
              </label>
              <Input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1" htmlFor="password">
                Пароль
              </label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
              />
            </div>

            <Button
              type="submit"
              className="w-full bg-blue-600 hover:bg-blue-700 text-white"
              disabled={loading}
            >
              {loading ? "Вход..." : "Войти"}
            </Button>
          </div>
        </form>


      </div>
    </div>
  );
}