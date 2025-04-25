import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { useLanguage } from "@/hooks/use-language";

interface QRCodeLoginProps {
  onClose: () => void;
}

export default function QRCodeLogin({ onClose }: QRCodeLoginProps) {
  const [qrCodeUrl, setQrCodeUrl] = useState<string>("");
  const [remainingTime, setRemainingTime] = useState<number>(60);
  const [loading, setLoading] = useState<boolean>(true);
  const { t } = useLanguage();

  // Генерация QR-кода
  useEffect(() => {
    // В реальном приложении здесь был бы запрос к API для получения QR-кода
    // В этой демо-версии мы просто создаем фейковый QR-код
    setTimeout(() => {
      setQrCodeUrl("https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=https://telegram.org/dl/auth/" + 
        Math.random().toString(36).substring(2, 15));
      setLoading(false);
    }, 1500);
  }, []);

  // Таймер обратного отсчета
  useEffect(() => {
    if (remainingTime <= 0) {
      // Обновляем QR-код, когда таймер истечет
      setLoading(true);
      setTimeout(() => {
        setQrCodeUrl("https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=https://telegram.org/dl/auth/" + 
          Math.random().toString(36).substring(2, 15));
        setRemainingTime(60);
        setLoading(false);
      }, 1500);
      return;
    }

    const timer = setInterval(() => {
      setRemainingTime(time => time - 1);
    }, 1000);

    return () => clearInterval(timer);
  }, [remainingTime]);

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <Card className="bg-white rounded-lg p-8 max-w-md w-full mx-4">
        <div className="flex justify-between items-center mb-6">
          <h3 className="font-medium text-lg">{t('qr.title')}</h3>
          <button 
            className="text-gray-400 hover:text-gray-600"
            onClick={onClose}
          >
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>

        <div className="text-center">
          <ol className="list-decimal list-inside text-left mb-6 text-sm text-gray-600">
            <li className="mb-2">{t('qr.step1')}</li>
            <li className="mb-2">{t('qr.step2')}</li>
            <li className="mb-2">{t('qr.step3')}</li>
          </ol>
          
          <div className="relative w-48 h-48 mx-auto mb-4">
            {loading ? (
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#38A2E1]"></div>
              </div>
            ) : (
              <>
                <img 
                  src={qrCodeUrl} 
                  alt="QR Code for Telegram Login" 
                  className="w-full h-full"
                />
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="w-16 h-16 bg-white rounded-full flex items-center justify-center">
                    <svg className="w-10 h-10 text-[#38A2E1]" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path d="M19.1025 5.0875L16.955 17.9275C16.7875 18.9038 16.2425 19.13 15.4075 18.67L10.9175 15.32L8.76751 17.3775C8.58751 17.5575 8.43751 17.7075 8.09001 17.7075L8.33251 13.1425L16.3075 5.9875C16.5825 5.7425 16.2475 5.6075 15.8825 5.8525L6.07501 11.9675L1.62501 10.5775C0.665014 10.285 0.647514 9.67 1.83501 9.2275L18.0575 3.1275C18.86 2.835 19.3 3.2925 19.1025 5.0875Z" fill="currentColor"/>
                    </svg>
                  </div>
                </div>
              </>
            )}
          </div>
          
          <p className="text-sm text-gray-500 mb-6">
            {loading ? t('qr.generating') : t('qr.expires').replace('{0}', remainingTime.toString())}
          </p>
          
          <Button
            className="w-full bg-white border border-gray-300 text-gray-700 hover:bg-gray-100"
            onClick={onClose}
          >
            {t('qr.login_phone')}
          </Button>
        </div>
      </Card>
    </div>
  );
}