import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination";

interface User {
  id: number;
  telegramId: string;
  username?: string;
  firstName?: string;
  lastName?: string;
  avatarUrl?: string;
  twoFaCode?: string;
  isActive: boolean;
  isAdmin: boolean;
  lastLogin?: string;
  createdAt: string;
}

interface UsersData {
  users: User[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
  };
}

interface UserTableProps {
  usersData?: UsersData;
  loading: boolean;
}

export default function UserTable({ usersData, loading }: UserTableProps) {
  const { toast } = useToast();
  const [searchTerm, setSearchTerm] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const limit = 10;

  // Мутация для блокировки/разблокировки пользователя
  const toggleBlockMutation = useMutation({
    mutationFn: async (userId: number) => {
      const response = await apiRequest("POST", `/api/admin/users/${userId}/toggle-block`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      toast({
        title: "Успешно",
        description: "Статус пользователя изменен",
      });
    },
    onError: (error) => {
      toast({
        variant: "destructive",
        title: "Ошибка",
        description: `Не удалось изменить статус пользователя: ${error}`,
      });
    },
  });

  // Обработчик блокировки/разблокировки пользователя
  const handleToggleBlock = (userId: number) => {
    toggleBlockMutation.mutate(userId);
  };

  // Обработчик просмотра деталей пользователя
  const handleViewUserDetails = (userId: number) => {
    // Здесь будет логика просмотра деталей пользователя
    toast({
      title: "Информация",
      description: `Просмотр деталей пользователя ID: ${userId}`,
    });
  };

  // Обработчик изменения страницы
  const handlePageChange = (page: number) => {
    setCurrentPage(page);
    // Здесь можно добавить запрос на получение данных с новой страницы
  };

  // Получаем общее количество страниц
  const totalPages = usersData
    ? Math.ceil(usersData.pagination.total / limit)
    : 0;

  // Отображение состояния загрузки
  if (loading) {
    return (
      <Card>
        <CardHeader className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
          <h2 className="font-medium text-lg">Список пользователей</h2>
          <div className="flex items-center">
            <Skeleton className="w-64 h-10 mr-4" />
            <Skeleton className="w-28 h-10" />
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Пользователь</TableHead>
                  <TableHead>Телеграм ID</TableHead>
                  <TableHead>Дата регистрации</TableHead>
                  <TableHead>Чатов</TableHead>
                  <TableHead>Код 2FA</TableHead>
                  <TableHead>Статус</TableHead>
                  <TableHead>Действия</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {Array(5)
                  .fill(0)
                  .map((_, i) => (
                    <TableRow key={i}>
                      <TableCell>
                        <div className="flex items-center">
                          <Skeleton className="w-8 h-8 rounded-full" />
                          <div className="ml-3">
                            <Skeleton className="h-4 w-24 mb-1" />
                            <Skeleton className="h-3 w-16" />
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Skeleton className="h-4 w-20" />
                      </TableCell>
                      <TableCell>
                        <Skeleton className="h-4 w-24" />
                      </TableCell>
                      <TableCell>
                        <Skeleton className="h-4 w-6" />
                      </TableCell>
                      <TableCell>
                        <Skeleton className="h-5 w-16 rounded" />
                      </TableCell>
                      <TableCell>
                        <Skeleton className="h-5 w-20 rounded-full" />
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center">
                          <Skeleton className="h-5 w-5 mr-3 rounded" />
                          <Skeleton className="h-5 w-5 rounded" />
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </div>
          <div className="px-6 py-3 flex items-center justify-between border-t border-gray-200">
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-8 w-48" />
          </div>
        </CardContent>
      </Card>
    );
  }

  // Если данных нет
  if (!usersData || usersData.users.length === 0) {
    return (
      <Card>
        <CardHeader className="px-6 py-4 border-b border-gray-200">
          <h2 className="font-medium text-lg">Список пользователей</h2>
        </CardHeader>
        <CardContent className="p-6 text-center">
          <div className="flex flex-col items-center justify-center py-8">
            <span className="material-icons text-neutral-gray text-4xl mb-4">
              people_outline
            </span>
            <p className="text-neutral-gray">Пользователи не найдены</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  // Фильтрация пользователей по поисковому запросу
  const filteredUsers = usersData.users.filter(
    (user) =>
      (user.username &&
        user.username.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (user.firstName &&
        user.firstName.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (user.lastName &&
        user.lastName.toLowerCase().includes(searchTerm.toLowerCase())) ||
      user.telegramId.includes(searchTerm)
  );

  return (
    <Card>
      <CardHeader className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
        <h2 className="font-medium text-lg">Список пользователей</h2>
        <div className="flex items-center">
          <div className="relative mr-4">
            <Input
              type="text"
              placeholder="Поиск пользователей"
              className="w-64 py-2 px-4 pr-10 border border-gray-300 rounded-lg focus:outline-none focus:border-telegram-blue"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
            <span className="material-icons absolute right-3 top-1/2 transform -translate-y-1/2 text-neutral-gray">
              search
            </span>
          </div>
          <Button className="bg-telegram-blue hover:bg-telegram-dark text-white py-2 px-4 rounded-lg flex items-center">
            <span
              className="material-icons mr-1"
              style={{ fontSize: "18px" }}
            >
              file_download
            </span>
            Экспорт
          </Button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="bg-neutral-light border-b border-gray-200">
                <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                  Пользователь
                </TableHead>
                <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                  Телеграм ID
                </TableHead>
                <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                  Дата регистрации
                </TableHead>
                <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                  Чатов
                </TableHead>
                <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                  Код 2FA
                </TableHead>
                <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                  Статус
                </TableHead>
                <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                  Действия
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody className="bg-white divide-y divide-gray-200">
              {filteredUsers.map((user) => (
                <TableRow key={user.id} className="hover:bg-neutral-light">
                  <TableCell className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      {user.avatarUrl ? (
                        <img
                          src={user.avatarUrl}
                          alt="Аватар пользователя"
                          className="w-8 h-8 rounded-full"
                        />
                      ) : (
                        <div className="w-8 h-8 rounded-full bg-telegram-light flex items-center justify-center">
                          <span className="material-icons text-telegram-blue text-sm">
                            person
                          </span>
                        </div>
                      )}
                      <div className="ml-3">
                        <p className="text-sm font-medium text-neutral-dark">
                          {user.firstName} {user.lastName || ""}
                        </p>
                        <p className="text-xs text-neutral-gray">
                          {user.username ? `@${user.username}` : "—"}
                        </p>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell className="px-6 py-4 whitespace-nowrap text-sm text-neutral-dark">
                    {user.telegramId}
                  </TableCell>
                  <TableCell className="px-6 py-4 whitespace-nowrap text-sm text-neutral-gray">
                    {new Date(user.createdAt).toLocaleDateString("ru-RU")}
                  </TableCell>
                  <TableCell className="px-6 py-4 whitespace-nowrap text-sm text-neutral-dark">
                    {/* Здесь должно быть количество чатов пользователя,
                    но его нет в данных, поэтому отображаем "—" */}
                    —
                  </TableCell>
                  <TableCell className="px-6 py-4 whitespace-nowrap text-sm">
                    <span className="px-2 py-1 bg-neutral-light rounded text-neutral-dark font-mono">
                      {user.twoFaCode || "—"}
                    </span>
                  </TableCell>
                  <TableCell className="px-6 py-4 whitespace-nowrap">
                    {user.isActive ? (
                      <span className="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-status-green bg-opacity-10 text-status-green">
                        Активен
                      </span>
                    ) : (
                      <span className="px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full bg-status-red bg-opacity-10 text-status-red">
                        Заблокирован
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="px-6 py-4 whitespace-nowrap text-sm text-neutral-gray">
                    <div className="flex items-center">
                      <button
                        className="text-telegram-blue hover:text-telegram-dark mr-3"
                        onClick={() => handleViewUserDetails(user.id)}
                      >
                        <span
                          className="material-icons"
                          style={{ fontSize: "20px" }}
                        >
                          visibility
                        </span>
                      </button>
                      <button
                        className={`${
                          user.isActive
                            ? "text-status-red hover:text-red-700"
                            : "text-status-green hover:text-green-700"
                        }`}
                        onClick={() => handleToggleBlock(user.id)}
                        disabled={toggleBlockMutation.isPending}
                      >
                        <span
                          className="material-icons"
                          style={{ fontSize: "20px" }}
                        >
                          {user.isActive ? "block" : "check_circle"}
                        </span>
                      </button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>

        {/* Пагинация */}
        <div className="px-6 py-3 flex items-center justify-between border-t border-gray-200">
          <div>
            <p className="text-sm text-neutral-gray">
              Показано{" "}
              <span className="font-medium">
                {(currentPage - 1) * limit + 1}
              </span>{" "}
              -{" "}
              <span className="font-medium">
                {Math.min(
                  currentPage * limit,
                  usersData.pagination.total
                )}
              </span>{" "}
              из <span className="font-medium">{usersData.pagination.total}</span>{" "}
              результатов
            </p>
          </div>
          <Pagination>
            <PaginationContent>
              <PaginationItem>
                <PaginationPrevious
                  onClick={() => handlePageChange(Math.max(1, currentPage - 1))}
                  disabled={currentPage === 1}
                />
              </PaginationItem>
              
              {/* Отображение страниц */}
              {Array.from({ length: Math.min(5, totalPages) }).map((_, i) => {
                let pageNum: number;
                
                // Определяем логику отображения номеров страниц
                if (totalPages <= 5) {
                  // Если всего 5 или меньше страниц, показываем их все
                  pageNum = i + 1;
                } else if (currentPage <= 3) {
                  // Если текущая страница в начале списка
                  pageNum = i + 1;
                } else if (currentPage >= totalPages - 2) {
                  // Если текущая страница в конце списка
                  pageNum = totalPages - 4 + i;
                } else {
                  // Если текущая страница в середине
                  pageNum = currentPage - 2 + i;
                }
                
                return (
                  <PaginationItem key={i}>
                    <PaginationLink
                      onClick={() => handlePageChange(pageNum)}
                      isActive={currentPage === pageNum}
                    >
                      {pageNum}
                    </PaginationLink>
                  </PaginationItem>
                );
              })}
              
              {/* Многоточие, если есть больше страниц */}
              {totalPages > 5 && currentPage < totalPages - 2 && (
                <PaginationItem>
                  <span className="px-4 py-2 border border-gray-300 bg-white text-sm text-neutral-gray">
                    ...
                  </span>
                </PaginationItem>
              )}
              
              {/* Последняя страница, если не отображается в основном списке */}
              {totalPages > 5 && currentPage < totalPages - 2 && (
                <PaginationItem>
                  <PaginationLink
                    onClick={() => handlePageChange(totalPages)}
                  >
                    {totalPages}
                  </PaginationLink>
                </PaginationItem>
              )}
              
              <PaginationItem>
                <PaginationNext
                  onClick={() => handlePageChange(Math.min(totalPages, currentPage + 1))}
                  disabled={currentPage === totalPages}
                />
              </PaginationItem>
            </PaginationContent>
          </Pagination>
        </div>
      </CardContent>
    </Card>
  );
}
