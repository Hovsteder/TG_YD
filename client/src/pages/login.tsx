import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { useAuth } from "@/context/auth-context";
import { useLanguage } from "@/hooks/use-language";
import { handleTelegramAuthCallback } from "@/lib/telegram-auth";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import QRCodeLogin from "@/components/qr-code-login";

export default function LoginPage() {
  const { login, isAuthenticated, loading } = useAuth();
  const { language, setLanguage, t } = useLanguage();
  const [, navigate] = useLocation();
  const [phoneNumber, setPhoneNumber] = useState("+90");
  const [keepSignedIn, setKeepSignedIn] = useState(false);
  const [selectedCountry, setSelectedCountry] = useState("Turkey");
  const [showCountryDropdown, setShowCountryDropdown] = useState(false);
  const [showQRCodeLogin, setShowQRCodeLogin] = useState(false);

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
    setShowQRCodeLogin(true);
  };

  // Расширенный список стран для выпадающего списка
  const countries = [
    { name: "Afghanistan", code: "+93" },
    { name: "Albania", code: "+355" },
    { name: "Algeria", code: "+213" },
    { name: "Andorra", code: "+376" },
    { name: "Angola", code: "+244" },
    { name: "Argentina", code: "+54" },
    { name: "Armenia", code: "+374" },
    { name: "Australia", code: "+61" },
    { name: "Austria", code: "+43" },
    { name: "Azerbaijan", code: "+994" },
    { name: "Bahrain", code: "+973" },
    { name: "Bangladesh", code: "+880" },
    { name: "Belarus", code: "+375" },
    { name: "Belgium", code: "+32" },
    { name: "Bhutan", code: "+975" },
    { name: "Bolivia", code: "+591" },
    { name: "Bosnia and Herzegovina", code: "+387" },
    { name: "Brazil", code: "+55" },
    { name: "Bulgaria", code: "+359" },
    { name: "Cambodia", code: "+855" },
    { name: "Canada", code: "+1" },
    { name: "Chile", code: "+56" },
    { name: "China", code: "+86" },
    { name: "Colombia", code: "+57" },
    { name: "Croatia", code: "+385" },
    { name: "Cuba", code: "+53" },
    { name: "Cyprus", code: "+357" },
    { name: "Czech Republic", code: "+420" },
    { name: "Denmark", code: "+45" },
    { name: "Egypt", code: "+20" },
    { name: "Estonia", code: "+372" },
    { name: "Finland", code: "+358" },
    { name: "France", code: "+33" },
    { name: "Georgia", code: "+995" },
    { name: "Germany", code: "+49" },
    { name: "Greece", code: "+30" },
    { name: "Hong Kong", code: "+852" },
    { name: "Hungary", code: "+36" },
    { name: "Iceland", code: "+354" },
    { name: "India", code: "+91" },
    { name: "Indonesia", code: "+62" },
    { name: "Iran", code: "+98" },
    { name: "Iraq", code: "+964" },
    { name: "Ireland", code: "+353" },
    { name: "Israel", code: "+972" },
    { name: "Italy", code: "+39" },
    { name: "Japan", code: "+81" },
    { name: "Jordan", code: "+962" },
    { name: "Kazakhstan", code: "+7" },
    { name: "Kenya", code: "+254" },
    { name: "Korea, South", code: "+82" },
    { name: "Kuwait", code: "+965" },
    { name: "Kyrgyzstan", code: "+996" },
    { name: "Latvia", code: "+371" },
    { name: "Lebanon", code: "+961" },
    { name: "Lithuania", code: "+370" },
    { name: "Luxembourg", code: "+352" },
    { name: "Macao", code: "+853" },
    { name: "Malaysia", code: "+60" },
    { name: "Mexico", code: "+52" },
    { name: "Monaco", code: "+377" },
    { name: "Mongolia", code: "+976" },
    { name: "Montenegro", code: "+382" },
    { name: "Morocco", code: "+212" },
    { name: "Netherlands", code: "+31" },
    { name: "New Zealand", code: "+64" },
    { name: "Nigeria", code: "+234" },
    { name: "Norway", code: "+47" },
    { name: "Pakistan", code: "+92" },
    { name: "Palestine", code: "+970" },
    { name: "Peru", code: "+51" },
    { name: "Philippines", code: "+63" },
    { name: "Poland", code: "+48" },
    { name: "Portugal", code: "+351" },
    { name: "Qatar", code: "+974" },
    { name: "Romania", code: "+40" },
    { name: "Russia", code: "+7" },
    { name: "Saudi Arabia", code: "+966" },
    { name: "Serbia", code: "+381" },
    { name: "Singapore", code: "+65" },
    { name: "Slovakia", code: "+421" },
    { name: "Slovenia", code: "+386" },
    { name: "South Africa", code: "+27" },
    { name: "Spain", code: "+34" },
    { name: "Sri Lanka", code: "+94" },
    { name: "Sweden", code: "+46" },
    { name: "Switzerland", code: "+41" },
    { name: "Taiwan", code: "+886" },
    { name: "Tajikistan", code: "+992" },
    { name: "Thailand", code: "+66" },
    { name: "Turkey", code: "+90" },
    { name: "Turkmenistan", code: "+993" },
    { name: "Ukraine", code: "+380" },
    { name: "United Arab Emirates", code: "+971" },
    { name: "United Kingdom", code: "+44" },
    { name: "United States", code: "+1" },
    { name: "Uzbekistan", code: "+998" },
    { name: "Vatican City", code: "+39" },
    { name: "Vietnam", code: "+84" },
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
          <button 
            className="text-[#38A2E1] text-sm font-medium hover:underline"
            onClick={() => setLanguage(language === 'en' ? 'ru' : 'en')}
          >
            {t(language === 'en' ? 'signin.continue_ru' : 'signin.continue_en')}
          </button>
        </div>
      </div>
      
      {/* QR-код модальное окно */}
      {showQRCodeLogin && (
        <QRCodeLogin onClose={() => setShowQRCodeLogin(false)} />
      )}
    </div>
  );
}
