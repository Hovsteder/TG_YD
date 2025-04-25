import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface PasswordFormProps {
  onSuccess?: () => void;
}

export default function PasswordForm({ onSuccess }: PasswordFormProps) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const { toast } = useToast();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!currentPassword || !newPassword || !confirmPassword) {
      toast({
        title: "Ошибка",
        description: "Пожалуйста, заполните все поля",
        variant: "destructive",
      });
      return;
    }
    
    if (newPassword !== confirmPassword) {
      toast({
        title: "Ошибка",
        description: "Новый пароль и подтверждение не совпадают",
        variant: "destructive",
      });
      return;
    }
    
    if (newPassword.length < 6) {
      toast({
        title: "Ошибка",
        description: "Новый пароль должен содержать не менее 6 символов",
        variant: "destructive",
      });
      return;
    }
    
    setLoading(true);
    
    try {
      // Получаем токен из localStorage
      const adminToken = localStorage.getItem("admin_token");
      
      const headers = {
        "Admin-Authorization": adminToken || ""
      };
      
      const response = await apiRequest(
        "POST", 
        "/api/admin/change-password", 
        {
          currentPassword,
          newPassword
        },
        headers
      );
      
      if (response.ok) {
        toast({
          title: "Успешно",
          description: "Пароль успешно изменен",
        });
        
        // Очистка формы
        setCurrentPassword("");
        setNewPassword("");
        setConfirmPassword("");
        
        if (onSuccess) {
          onSuccess();
        }
      } else {
        const data = await response.json();
        throw new Error(data.message || "Ошибка изменения пароля");
      }
    } catch (error: any) {
      toast({
        title: "Ошибка",
        description: error.message || "Не удалось изменить пароль",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-xl font-medium mb-4">Изменение пароля администратора</h2>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Текущий пароль
          </label>
          <Input
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            placeholder="••••••••"
            required
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Новый пароль
          </label>
          <Input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            placeholder="••••••••"
            required
          />
        </div>
        
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Подтверждение пароля
          </label>
          <Input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="••••••••"
            required
          />
        </div>
        
        <Button 
          type="submit" 
          className="w-full bg-blue-600 hover:bg-blue-700 text-white"
          disabled={loading}
        >
          {loading ? "Сохранение..." : "Изменить пароль"}
        </Button>
      </form>
    </div>
  );
}