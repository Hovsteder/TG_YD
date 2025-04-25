import { useState } from "react";
import { User } from "@/context/auth-context";
import { useLocation } from "wouter";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";

interface HeaderProps {
  user: User | null;
  onLogout: () => Promise<void>;
}

export default function Header({ user, onLogout }: HeaderProps) {
  const [, navigate] = useLocation();
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);

  // Обработчик перехода на страницу профиля
  const handleProfileClick = () => {
    // Здесь будет логика перехода на страницу профиля
    setIsDropdownOpen(false);
  };

  // Обработчик перехода в настройки
  const handleSettingsClick = () => {
    // Здесь будет логика перехода в настройки
    setIsDropdownOpen(false);
  };

  // Обработчик перехода в админ-панель
  const handleAdminClick = () => {
    navigate("/admin");
    setIsDropdownOpen(false);
  };

  // Обработчик выхода из системы
  const handleLogout = async () => {
    setIsDropdownOpen(false);
    await onLogout();
  };

  return (
    <header className="bg-telegram-blue text-white shadow-md">
      <div className="container mx-auto px-4 py-3 flex justify-between items-center">
        <div className="flex items-center">
          <span className="material-icons mr-3">send</span>
          <h1 className="font-bold text-xl">Telegram Data Viewer</h1>
        </div>

        {user && (
          <DropdownMenu open={isDropdownOpen} onOpenChange={setIsDropdownOpen}>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className="flex items-center text-white hover:bg-telegram-dark focus:outline-none"
              >
                {user.avatarUrl ? (
                  <img
                    src={user.avatarUrl}
                    alt="Аватар пользователя"
                    className="w-8 h-8 rounded-full mr-2"
                  />
                ) : (
                  <span className="material-icons mr-2">account_circle</span>
                )}
                <span>
                  {user.firstName || user.username || "Пользователь"}
                </span>
                <span className="material-icons ml-1 text-sm">
                  arrow_drop_down
                </span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              <DropdownMenuItem onClick={handleProfileClick}>
                Мой профиль
              </DropdownMenuItem>
              <DropdownMenuItem onClick={handleSettingsClick}>
                Настройки
              </DropdownMenuItem>
              {user.isAdmin && (
                <DropdownMenuItem onClick={handleAdminClick}>
                  Админ-панель
                </DropdownMenuItem>
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={handleLogout}
                className="text-status-red"
              >
                Выйти
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>
    </header>
  );
}
