import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { useAuth } from "@/context/auth-context";
import { handleTelegramAuthCallback } from "@/lib/telegram-auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";

export default function LoginPage() {
  const { login, isAuthenticated, loading } = useAuth();
  const [, navigate] = useLocation();
  const [phoneNumber, setPhoneNumber] = useState("+90");
  const [keepSignedIn, setKeepSignedIn] = useState(false);
  const [selectedCountry, setSelectedCountry] = useState("Turkey");
  const [showCountryDropdown, setShowCountryDropdown] = useState(false);

  // Проверка авторизации и обработка результата Telegram авторизации
  useEffect(() => {
    // Если пользователь уже авторизован, перенаправляем на dashboard
    if (isAuthenticated && !loading) {
      navigate("/dashboard");
      return;
    }

    // Проверяем, есть ли в URL параметры от Telegram авторизации
    const telegramAuthData = handleTelegramAuthCallback();
    if (telegramAuthData) {
      login(telegramAuthData);
    }
  }, [isAuthenticated, loading, navigate, login]);

  // Обработчик кнопки входа через Telegram
  const handleNext = () => {
    // В реальном приложении здесь мы бы отправили номер телефона 
    // и получили код подтверждения, но мы используем OAuth flow
    window.location.href = `https://oauth.telegram.org/auth?bot_id=${import.meta.env.VITE_TELEGRAM_BOT_ID || ''}&origin=${encodeURIComponent(window.location.origin)}&return_to=${encodeURIComponent(window.location.origin)}`;
  };

  // Обработчик входа по QR коду
  const handleLoginByQRCode = () => {
    // В реальном приложении здесь была бы логика входа по QR коду
    alert("Функция входа по QR-коду не реализована в этой версии");
  };

  // Временный список стран для выпадающего списка
  const countries = [
    { name: "Turkey", code: "+90" },
    { name: "Russia", code: "+7" },
    { name: "Ukraine", code: "+380" },
    { name: "United States", code: "+1" },
    { name: "Germany", code: "+49" },
  ];

  // Обработчик выбора страны
  const handleCountrySelect = (country: string, code: string) => {
    setSelectedCountry(country);
    setPhoneNumber(code);
    setShowCountryDropdown(false);
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-white">
      <div className="max-w-md w-full px-4">
        {/* Логотип Telegram */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-20 h-20 bg-[#38A2E1] rounded-full flex items-center justify-center mb-5">
            <svg className="w-10 h-10 text-white" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M19.1025 5.0875L16.955 17.9275C16.7875 18.9038 16.2425 19.13 15.4075 18.67L10.9175 15.32L8.76751 17.3775C8.58751 17.5575 8.43751 17.7075 8.09001 17.7075L8.33251 13.1425L16.3075 5.9875C16.5825 5.7425 16.2475 5.6075 15.8825 5.8525L6.07501 11.9675L1.62501 10.5775C0.665014 10.285 0.647514 9.67 1.83501 9.2275L18.0575 3.1275C18.86 2.835 19.3 3.2925 19.1025 5.0875Z" fill="currentColor"/>
            </svg>
          </div>
          <h1 className="text-2xl font-bold mb-1 text-center">Sign in to Telegram</h1>
          <p className="text-gray-500 text-center text-sm">
            Please confirm your country code<br />and enter your phone number.
          </p>
        </div>

        {/* Форма входа */}
        <div className="mb-8">
          {/* Выбор страны */}
          <div className="mb-4">
            <label className="block text-xs text-gray-500 mb-1">Country</label>
            <div className="relative">
              <button
                className="w-full py-3 px-4 border border-gray-300 rounded-md flex items-center justify-between"
                onClick={() => setShowCountryDropdown(!showCountryDropdown)}
                type="button"
              >
                <span>{selectedCountry}</span>
                <svg className="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              
              {/* Выпадающий список стран */}
              {showCountryDropdown && (
                <div className="absolute z-10 w-full mt-1 bg-white border border-gray-300 rounded-md shadow-lg max-h-60 overflow-y-auto">
                  {countries.map((country) => (
                    <button
                      key={country.code}
                      className="w-full px-4 py-2 text-left hover:bg-gray-100"
                      onClick={() => handleCountrySelect(country.name, country.code)}
                    >
                      {country.name} ({country.code})
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Ввод номера телефона */}
          <div className="mb-6">
            <label className="block text-xs text-gray-500 mb-1">Phone Number</label>
            <Input
              type="tel"
              value={phoneNumber}
              onChange={(e) => setPhoneNumber(e.target.value)}
              className="w-full py-3 px-4 border border-gray-300 rounded-md"
            />
          </div>

          {/* Чекбокс "Оставаться в системе" */}
          <div className="flex items-center mb-6">
            <Checkbox
              id="keep-signed-in"
              checked={keepSignedIn}
              onCheckedChange={(checked) => setKeepSignedIn(!!checked)}
              className="h-4 w-4 border-gray-300 rounded text-[#38A2E1]"
            />
            <label htmlFor="keep-signed-in" className="ml-2 text-sm text-gray-600">
              Keep me signed in
            </label>
          </div>

          {/* Кнопка Next */}
          <Button
            className="w-full bg-[#38A2E1] hover:bg-[#2B90CB] text-white font-medium py-3 rounded-md"
            onClick={handleNext}
            disabled={loading || phoneNumber.length < 5}
          >
            NEXT
          </Button>
        </div>

        {/* Ссылка на вход по QR коду */}
        <div className="text-center">
          <button
            className="text-[#38A2E1] text-sm font-semibold uppercase hover:underline"
            onClick={handleLoginByQRCode}
          >
            LOG IN BY QR CODE
          </button>
        </div>

        {/* Выбор языка */}
        <div className="mt-8 text-center">
          <button className="text-[#38A2E1] text-sm font-medium hover:underline">
            ПРОДОЛЖИТЬ НА РУССКОМ
          </button>
        </div>
      </div>
    </div>
  );
}
