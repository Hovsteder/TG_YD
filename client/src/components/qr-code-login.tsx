import { useState, useEffect, useCallback } from "react";
import * as QRCodeLib from "qrcode.react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Loader2, X } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface QRCodeLoginProps {
  onClose: () => void;
  onLoginSuccess?: (userData: any) => void;
}

export default function QRCodeLogin({ onClose, onLoginSuccess }: QRCodeLoginProps) {
  const [loading, setLoading] = useState(true);
  const [qrData, setQrData] = useState<{
    token: string;
    url: string;
    expires: number;
  } | null>(null);
  const [checkStatus, setCheckStatus] = useState<{
    checking: boolean;
    interval: NodeJS.Timeout | null;
  }>({ checking: false, interval: null });
  const { toast } = useToast();

  // Функция для создания QR-кода
  const createQRCode = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch("/api/auth/qr/create", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
      });

      const data = await response.json();
      if (data.success && data.token && data.url) {
        setQrData({
          token: data.token,
          url: data.url,
          expires: data.expires || 300, // По умолчанию 5 минут
        });
        
        // Запускаем проверку статуса
        startStatusCheck(data.token);
      } else {
        toast({
          title: "Ошибка создания QR-кода",
          description: data.message || "Не удалось создать QR-код для входа",
          variant: "destructive",
        });
      }
    } catch (error) {
      console.error("Error creating QR code:", error);
      toast({
        title: "Ошибка",
        description: "Произошла ошибка при создании QR-кода",
        variant: "destructive",
      });
    } finally {
      setLoading(false);
    }
  }, [toast]);
  
  // Функция для начала проверки статуса
  const startStatusCheck = useCallback((token: string) => {
    // Если уже есть интервал, очищаем его
    if (checkStatus.interval) {
      clearInterval(checkStatus.interval);
    }
    
    // Создаем новый интервал для проверки статуса каждые 3 секунды
    const interval = setInterval(async () => {
      try {
        // Устанавливаем флаг проверки
        setCheckStatus(prev => ({ ...prev, checking: true }));
        
        const response = await fetch("/api/auth/qr/check", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ token }),
        });
        
        const data = await response.json();
        
        // Если успешно авторизовались
        if (data.success && data.user) {
          // Останавливаем проверку
          clearInterval(interval);
          setCheckStatus({ checking: false, interval: null });
          
          // Отображаем сообщение об успешной авторизации
          toast({
            title: "Вход выполнен успешно",
            description: "Вы успешно авторизовались через QR-код",
          });
          
          // Вызываем функцию обратного вызова об успешном входе
          if (onLoginSuccess) {
            onLoginSuccess(data);
          }
          
          // Закрываем окно QR-кода
          onClose();
        } else if (!data.waiting) {
          // Если ошибка и это не ожидание сканирования
          toast({
            title: "Ошибка авторизации",
            description: data.message || "Не удалось авторизоваться через QR-код",
            variant: "destructive",
          });
        }
      } catch (error) {
        console.error("Error checking QR status:", error);
        toast({
          title: "Ошибка проверки",
          description: "Произошла ошибка при проверке статуса QR-кода",
          variant: "destructive",
        });
      } finally {
        // Снимаем флаг проверки
        setCheckStatus(prev => ({ ...prev, checking: false }));
      }
    }, 3000); // Проверяем каждые 3 секунды
    
    // Сохраняем интервал
    setCheckStatus({ checking: false, interval });
  }, [checkStatus.interval, onClose, onLoginSuccess, toast]);
  
  // Генерируем QR-код при монтировании компонента
  useEffect(() => {
    createQRCode();
    
    // Очистка интервала при размонтировании компонента
    return () => {
      if (checkStatus.interval) {
        clearInterval(checkStatus.interval);
      }
    };
  }, [createQRCode, checkStatus.interval]);
  
  // Обновить QR-код по запросу пользователя
  const handleRefresh = () => {
    createQRCode();
  };

  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader className="relative">
        <Button
          variant="ghost"
          size="icon"
          onClick={onClose}
          className="absolute right-2 top-2"
        >
          <X className="h-4 w-4" />
        </Button>
        <CardTitle>Войти через QR-код</CardTitle>
        <CardDescription>
          Отсканируйте QR-код в приложении Telegram для быстрого входа
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col items-center">
        {loading ? (
          <div className="flex flex-col items-center justify-center p-10">
            <Loader2 className="h-16 w-16 animate-spin text-primary/80" />
            <p className="mt-4 text-sm text-gray-500">Загрузка QR-кода...</p>
          </div>
        ) : qrData ? (
          <div className="flex flex-col items-center">
            <div className="border border-gray-200 p-2 rounded-md">
              <QRCodeLib.QRCodeSVG value={qrData.url} size={220} />
            </div>
            <p className="mt-4 text-sm text-gray-500">
              Осталось времени: {Math.floor(qrData.expires / 60)}:{String(qrData.expires % 60).padStart(2, '0')}
            </p>
            <p className="text-xs text-gray-400 mt-1">
              QR-код действителен в течение {Math.floor(qrData.expires / 60)} минут
            </p>
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center p-10">
            <p className="text-sm text-gray-500">Не удалось загрузить QR-код</p>
          </div>
        )}

        {checkStatus.checking && (
          <div className="flex items-center mt-4">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />
            <p className="text-sm text-gray-500">Ожидание сканирования...</p>
          </div>
        )}
      </CardContent>
      <CardFooter className="flex justify-center">
        <Button 
          onClick={handleRefresh} 
          disabled={loading || checkStatus.checking}
          variant="outline"
        >
          {loading && <Loader2 className="h-4 w-4 animate-spin mr-2" />}
          Обновить QR-код
        </Button>
      </CardFooter>
    </Card>
  );
}