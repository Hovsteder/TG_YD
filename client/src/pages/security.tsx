import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { useAuth } from "@/context/auth-context";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import SecurityCodeInput from "@/components/security-code-input";

export default function SecurityPage() {
  const { telegramId, verify2FA, resend2FACode, isAuthenticated, loading } = useAuth();
  const [code, setCode] = useState<string>("");
  const [verifying, setVerifying] = useState<boolean>(false);
  const [resending, setResending] = useState<boolean>(false);
  const [remainingTime, setRemainingTime] = useState<number>(300); // 5 минут
  const [, navigate] = useLocation();

  // Перенаправление авторизованных пользователей
  useEffect(() => {
    if (isAuthenticated && !loading) {
      navigate("/dashboard");
    }
    
    // Перенаправление неинициализированных пользователей
    if (!telegramId && !loading) {
      navigate("/");
    }
  }, [isAuthenticated, telegramId, loading, navigate]);

  // Настройка таймера обратного отсчета
  useEffect(() => {
    if (remainingTime <= 0) return;
    
    const timer = setInterval(() => {
      setRemainingTime((prev) => Math.max(0, prev - 1));
    }, 1000);
    
    return () => clearInterval(timer);
  }, [remainingTime]);

  // Форматирование оставшегося времени
  const formatRemainingTime = () => {
    const minutes = Math.floor(remainingTime / 60);
    const seconds = remainingTime % 60;
    return `${minutes}:${seconds.toString().padStart(2, "0")}`;
  };

  // Обработчик проверки кода
  const handleVerifyCode = async () => {
    if (!telegramId || code.length !== 5 || verifying) return;
    
    setVerifying(true);
    try {
      await verify2FA(telegramId, code);
    } finally {
      setVerifying(false);
    }
  };

  // Обработчик повторной отправки кода
  const handleResendCode = async () => {
    if (!telegramId || resending || remainingTime > 0) return;
    
    setResending(true);
    try {
      const success = await resend2FACode(telegramId);
      if (success) {
        setRemainingTime(300); // Сбрасываем таймер
      }
    } finally {
      setResending(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6 bg-neutral-light">
      <Card className="w-full max-w-md overflow-hidden">
        <div className="bg-telegram-blue p-6 text-white text-center">
          <h1 className="text-2xl font-bold">Двухфакторная аутентификация</h1>
          <p className="mt-1 text-sm opacity-90">Введите код безопасности для продолжения</p>
        </div>
        
        <CardContent className="p-6">
          <div className="flex flex-col items-center">
            <div className="bg-telegram-light rounded-full p-4 mb-6">
              <span className="material-icons text-4xl text-telegram-blue">security</span>
            </div>
            
            <p className="text-center mb-6 text-neutral-gray">
              На ваш Telegram был отправлен одноразовый код подтверждения. Введите его ниже.
            </p>
            
            <div className="w-full mb-6">
              <SecurityCodeInput
                value={code}
                onChange={setCode}
                disabled={verifying}
                onComplete={handleVerifyCode}
              />
            </div>
            
            <Button 
              className="w-full bg-telegram-blue hover:bg-telegram-dark text-white py-3 px-6 rounded-full flex items-center justify-center"
              onClick={handleVerifyCode}
              disabled={code.length !== 5 || verifying}
            >
              <span className="material-icons mr-2">check</span>
              {verifying ? "Проверка..." : "Подтвердить"}
            </Button>
            
            <p className="mt-4 text-sm text-neutral-gray">
              {remainingTime > 0 ? (
                <>Повторная отправка возможна через {formatRemainingTime()}</>
              ) : (
                <>
                  Не получили код?{" "}
                  <button
                    className="text-telegram-blue hover:underline"
                    onClick={handleResendCode}
                    disabled={resending}
                  >
                    {resending ? "Отправка..." : "Отправить повторно"}
                  </button>
                </>
              )}
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
