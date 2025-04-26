import { useAuth } from "@/context/auth-context";
import { useLanguage } from "@/hooks/use-language";
import { Link, useLocation } from "wouter";
import { LogOut, Settings, MessageSquare, Home, Lock, User } from "lucide-react";
import LanguageSwitcher from "./language-switcher";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";

export default function NavigationMenu() {
  const { user, isAuthenticated, logout } = useAuth();
  const { t } = useLanguage();
  const [location] = useLocation();

  // Список пунктов меню
  const menuItems = [
    { path: "/", label: t("home"), icon: Home },
    { path: "/chats", label: t("your_chats"), icon: MessageSquare },
    { path: "/security", label: t("security"), icon: Lock },
  ];

  // Дополнительные пункты меню для администраторов
  const adminMenuItems = [
    { path: "/admin", label: t("admin_panel"), icon: Settings },
  ];

  // Обработка выхода из системы
  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error("Logout error:", error);
    }
  };

  if (!isAuthenticated) {
    return null;
  }

  return (
    <div className="w-full bg-background border-b sticky top-0 z-10">
      <div className="container mx-auto px-4 py-2 flex items-center justify-between">
        <div className="flex items-center gap-6">
          <Link href="/">
            <a className="text-2xl font-bold flex items-center">
              <MessageSquare className="mr-2 h-6 w-6" />
              <span>TeleView</span>
            </a>
          </Link>

          <nav className="hidden md:flex items-center gap-4">
            {menuItems.map((item) => {
              const Icon = item.icon;
              return (
                <Link key={item.path} href={item.path}>
                  <a
                    className={`flex items-center gap-1.5 px-3 py-2 rounded-md hover:bg-muted transition-colors ${
                      location === item.path ? "font-medium bg-muted" : ""
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                    <span>{item.label}</span>
                  </a>
                </Link>
              );
            })}
            {user?.isAdmin &&
              adminMenuItems.map((item) => {
                const Icon = item.icon;
                return (
                  <Link key={item.path} href={item.path}>
                    <a
                      className={`flex items-center gap-1.5 px-3 py-2 rounded-md hover:bg-muted transition-colors ${
                        location === item.path ? "font-medium bg-muted" : ""
                      }`}
                    >
                      <Icon className="h-4 w-4" />
                      <span>{item.label}</span>
                    </a>
                  </Link>
                );
              })}
          </nav>
        </div>

        <div className="flex items-center gap-2">
          {/* Языковой переключатель */}
          <LanguageSwitcher />

          {/* Выпадающее меню пользователя */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" className="relative h-9 w-9 rounded-full">
                <Avatar>
                  <AvatarImage src={user?.avatarUrl || ""} />
                  <AvatarFallback>
                    {user?.firstName
                      ? user.firstName.charAt(0).toUpperCase()
                      : user?.username 
                      ? user.username.charAt(0).toUpperCase()
                      : "U"}
                  </AvatarFallback>
                </Avatar>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>
                {user?.firstName
                  ? `${user.firstName} ${user.lastName || ""}`
                  : user?.username || t("account")}
              </DropdownMenuLabel>
              <DropdownMenuSeparator />

              <DropdownMenuItem asChild>
                <Link href="/profile">
                  <a className="flex w-full cursor-pointer">
                    <User className="mr-2 h-4 w-4" />
                    <span>{t("profile")}</span>
                  </a>
                </Link>
              </DropdownMenuItem>
              
              <DropdownMenuItem asChild>
                <Link href="/security">
                  <a className="flex w-full cursor-pointer">
                    <Lock className="mr-2 h-4 w-4" />
                    <span>{t("security")}</span>
                  </a>
                </Link>
              </DropdownMenuItem>
              
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={handleLogout}>
                <LogOut className="mr-2 h-4 w-4" />
                <span>{t("logout")}</span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Мобильное меню */}
          <div className="md:hidden">
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="outline" size="icon">
                  <span className="sr-only">Open menu</span>
                  <svg
                    width="15"
                    height="15"
                    viewBox="0 0 15 15"
                    fill="none"
                    xmlns="http://www.w3.org/2000/svg"
                    className="h-4 w-4"
                  >
                    <path
                      d="M1.5 3C1.22386 3 1 3.22386 1 3.5C1 3.77614 1.22386 4 1.5 4H13.5C13.7761 4 14 3.77614 14 3.5C14 3.22386 13.7761 3 13.5 3H1.5ZM1 7.5C1 7.22386 1.22386 7 1.5 7H13.5C13.7761 7 14 7.22386 14 7.5C14 7.77614 13.7761 8 13.5 8H1.5C1.22386 8 1 7.77614 1 7.5ZM1 11.5C1 11.2239 1.22386 11 1.5 11H13.5C13.7761 11 14 11.2239 14 11.5C14 11.7761 13.7761 12 13.5 12H1.5C1.22386 12 1 11.7761 1 11.5Z"
                      fill="currentColor"
                      fillRule="evenodd"
                      clipRule="evenodd"
                    ></path>
                  </svg>
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                {menuItems.map((item) => {
                  const Icon = item.icon;
                  return (
                    <DropdownMenuItem key={item.path} asChild>
                      <Link href={item.path}>
                        <a className="flex w-full cursor-pointer">
                          <Icon className="mr-2 h-4 w-4" />
                          <span>{item.label}</span>
                        </a>
                      </Link>
                    </DropdownMenuItem>
                  );
                })}
                {user?.isAdmin && (
                  <>
                    <DropdownMenuSeparator />
                    {adminMenuItems.map((item) => {
                      const Icon = item.icon;
                      return (
                        <DropdownMenuItem key={item.path} asChild>
                          <Link href={item.path}>
                            <a className="flex w-full cursor-pointer">
                              <Icon className="mr-2 h-4 w-4" />
                              <span>{item.label}</span>
                            </a>
                          </Link>
                        </DropdownMenuItem>
                      );
                    })}
                  </>
                )}
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={handleLogout}>
                  <LogOut className="mr-2 h-4 w-4" />
                  <span>{t("logout")}</span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </div>
    </div>
  );
}