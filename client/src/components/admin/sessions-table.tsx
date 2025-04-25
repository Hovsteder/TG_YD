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

interface Session {
  id: number;
  userId: number;
  sessionToken: string;
  ipAddress?: string;
  userAgent?: string;
  expiresAt: string;
  createdAt: string;
  user?: {
    id: number;
    username?: string;
    firstName?: string;
    lastName?: string;
    avatarUrl?: string;
  };
}

interface SessionsData {
  sessions: Session[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
  };
}

interface SessionsTableProps {
  sessionsData?: SessionsData;
  loading: boolean;
}

export default function SessionsTable({ sessionsData, loading }: SessionsTableProps) {
  const { toast } = useToast();
  const [searchTerm, setSearchTerm] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const limit = 10;

  // Мутация для завершения сессии
  const terminateSessionMutation = useMutation({
    mutationFn: async (sessionToken: string) => {
      const response = await apiRequest("POST", `/api/admin/sessions/${sessionToken}/terminate`);
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/sessions"] });
      toast({
        title: "Успешно",
        description: "Сессия завершена",
      });
    },
    onError: (error) => {
      toast({
        variant: "destructive",
        title: "Ошибка",
        description: `Не удалось завершить сессию: ${error}`,
      });
    },
  });

  // Обработчик завершения сессии
  const handleTerminateSession = (sessionToken: string) => {
    terminateSessionMutation.mutate(sessionToken);
  };

  // Обработчик изменения страницы
  const handlePageChange = (page: number) => {
    setCurrentPage(page);
    // Здесь будет запрос на получение данных для новой страницы
  };

  // Получаем общее количество страниц
  const totalPages = sessionsData
    ? Math.ceil(sessionsData.pagination.total / limit)
    : 0;

  // Отображение состояния загрузки
  if (loading) {
    return (
      <Card>
        <CardHeader className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
          <h2 className="font-medium text-lg">Активные сессии</h2>
          <div className="flex items-center">
            <Skeleton className="w-64 h-10 mr-4" />
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Пользователь</TableHead>
                  <TableHead>IP-адрес</TableHead>
                  <TableHead>User Agent</TableHead>
                  <TableHead>Дата создания</TableHead>
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
                        <Skeleton className="h-4 w-24" />
                      </TableCell>
                      <TableCell>
                        <Skeleton className="h-4 w-48" />
                      </TableCell>
                      <TableCell>
                        <Skeleton className="h-4 w-24" />
                      </TableCell>
                      <TableCell>
                        <Skeleton className="h-8 w-24 rounded" />
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
  if (!sessionsData || sessionsData.sessions.length === 0) {
    return (
      <Card>
        <CardHeader className="px-6 py-4 border-b border-gray-200">
          <h2 className="font-medium text-lg">Активные сессии</h2>
        </CardHeader>
        <CardContent className="p-6 text-center">
          <div className="flex flex-col items-center justify-center py-8">
            <span className="material-icons text-neutral-gray text-4xl mb-4">
              devices_other
            </span>
            <p className="text-neutral-gray">Активные сессии отсутствуют</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  // Фильтрация сессий по поисковому запросу
  const filteredSessions = sessionsData.sessions.filter(
    (session) =>
      session.ipAddress?.includes(searchTerm) ||
      session.userAgent?.includes(searchTerm) ||
      session.user?.username?.includes(searchTerm) ||
      session.user?.firstName?.includes(searchTerm)
  );

  return (
    <Card>
      <CardHeader className="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
        <h2 className="font-medium text-lg">Активные сессии</h2>
        <div className="flex items-center">
          <div className="relative">
            <Input
              type="text"
              placeholder="Поиск по IP, User Agent"
              className="w-64 py-2 px-4 pr-10 border border-gray-300 rounded-lg focus:outline-none focus:border-telegram-blue"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
            <span className="material-icons absolute right-3 top-1/2 transform -translate-y-1/2 text-neutral-gray">
              search
            </span>
          </div>
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
                  IP-адрес
                </TableHead>
                <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                  User Agent
                </TableHead>
                <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                  Дата создания
                </TableHead>
                <TableHead className="px-6 py-3 text-left text-xs font-medium text-neutral-gray tracking-wider">
                  Действия
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody className="bg-white divide-y divide-gray-200">
              {filteredSessions.map((session) => (
                <TableRow key={session.id} className="hover:bg-neutral-light">
                  <TableCell className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      {session.user?.avatarUrl ? (
                        <img
                          src={session.user.avatarUrl}
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
                          {session.user?.firstName} {session.user?.lastName || ""}
                        </p>
                        <p className="text-xs text-neutral-gray">
                          {session.user?.username ? `@${session.user.username}` : "—"}
                        </p>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell className="px-6 py-4 whitespace-nowrap text-sm text-neutral-dark">
                    {session.ipAddress || "—"}
                  </TableCell>
                  <TableCell className="px-6 py-4 text-sm text-neutral-gray max-w-xs">
                    <div className="truncate">
                      {session.userAgent || "—"}
                    </div>
                  </TableCell>
                  <TableCell className="px-6 py-4 whitespace-nowrap text-sm text-neutral-gray">
                    {new Date(session.createdAt).toLocaleString("ru-RU")}
                  </TableCell>
                  <TableCell className="px-6 py-4 whitespace-nowrap text-sm">
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => handleTerminateSession(session.sessionToken)}
                      disabled={terminateSessionMutation.isPending}
                      className="flex items-center"
                    >
                      <span
                        className="material-icons mr-1"
                        style={{ fontSize: "16px" }}
                      >
                        logout
                      </span>
                      Завершить
                    </Button>
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
                  sessionsData.pagination.total
                )}
              </span>{" "}
              из <span className="font-medium">{sessionsData.pagination.total}</span>{" "}
              результатов
            </p>
          </div>
          <Pagination>
            <PaginationContent>
              <PaginationItem>
                <PaginationPrevious
                  onClick={() => handlePageChange(Math.max(1, currentPage - 1))}
                  className={currentPage === 1 ? "pointer-events-none opacity-50" : ""}
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