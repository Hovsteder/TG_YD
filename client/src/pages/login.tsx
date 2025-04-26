import { Fragment, useEffect, useState } from "react";
import { useLocation } from "wouter";
import { useAuth } from "@/context/auth-context";
import { useLanguage } from "@/hooks/use-language";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import SecurityCodeInput from "@/components/security-code-input";
import QRCodeLogin from "@/components/qr-code-login";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { ZodError, z } from "zod";
import { useToast } from "@/hooks/use-toast";
import { Loader2, Smartphone, QrCode } from "lucide-react";
// Убрали импорт неиспользуемых функций из telegram-auth

// Шаги процесса аутентификации
enum AuthStep {
  PHONE_INPUT, // Ввод номера телефона
  CODE_VERIFICATION, // Верификация кода
  PASSWORD_LOGIN, // Вход с паролем
  REGISTER, // Регистрация (установка пароля)
}

export default function LoginPage() {
  // Хуки и состояния
  const { requestPhoneCode, verifyPhoneCode, setupPassword, loginWithPassword, isAuthenticated, loading } = useAuth();
  const { language, setLanguage, t } = useLanguage();
  const [, navigate] = useLocation();
  const { toast } = useToast();
  
  // Состояния для формы
  const [phoneNumber, setPhoneNumber] = useState("+90");
  const [keepSignedIn, setKeepSignedIn] = useState(false);
  const [selectedCountry, setSelectedCountry] = useState("Turkey");
  const [showCountryDropdown, setShowCountryDropdown] = useState(false);
  const [authStep, setAuthStep] = useState<AuthStep>(AuthStep.PHONE_INPUT);
  const [verificationCode, setVerificationCode] = useState("");
  const [isNewUser, setIsNewUser] = useState(false);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [email, setEmail] = useState("");
  const [tabValue, setTabValue] = useState("phone"); // Активная вкладка: phone или admin
  const [showQRCodeModal, setShowQRCodeModal] = useState(false); // Состояние для модального окна QR-кода
  
  // Обработчик успешного QR-входа
  const handleQRLoginSuccess = (data: any) => {
    // Закрываем модальное окно
    setShowQRCodeModal(false);
    
    // Используем данные пользователя для входа
    if (data.success && data.user && data.sessionToken) {
      toast({
        title: "Успешный вход",
        description: "Вы успешно вошли через QR-код",
      });
      
      // Перенаправляем на страницу админа или дашборда
      if (data.user.isAdmin) {
        navigate("/admin");
      } else {
        navigate("/dashboard");
      }
    }
  };

  // Проверка авторизации
  useEffect(() => {
    // Если пользователь уже авторизован, перенаправляем на страницу чатов
    if (isAuthenticated && !loading) {
      navigate("/chats");
    }
  }, [isAuthenticated, loading, navigate]);

  // Обработчик для кнопки "Далее" при вводе номера телефона
  const handleRequestCode = async () => {
    try {
      // Валидация номера телефона
      if (phoneNumber.length < 8) {
        toast({
          variant: "destructive",
          title: "Ошибка",
          description: "Пожалуйста, введите корректный номер телефона",
        });
        return;
      }
      
      // Запрос кода подтверждения
      const success = await requestPhoneCode(phoneNumber);
      
      if (success) {
        setAuthStep(AuthStep.CODE_VERIFICATION);
        
        // Информировать пользователя о том, что код отправлен в Telegram
        toast({
          title: "Код отправлен в Telegram",
          description: "Проверьте ваши сообщения в Telegram для получения кода подтверждения",
        });
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Ошибка отправки кода",
        description: "Не удалось отправить код подтверждения",
      });
    }
  };

  // Функция-заглушка для предотвращения ошибок при ссылках на удаленные функции
  // Может быть удалена позже, когда все ссылки будут обновлены
  const initTelegramWidget = () => {
    console.log("Функция была удалена при обновлении системы аутентификации");
  }

  // Обработчик для проверки кода подтверждения
  const handleVerifyCode = async () => {
    try {
      // Валидация кода
      if (verificationCode.length !== 5) {
        toast({
          variant: "destructive",
          title: "Неверный код",
          description: "Код должен содержать 5 цифр",
        });
        return;
      }

      // Проверка кода
      const result = await verifyPhoneCode(phoneNumber, verificationCode);
      
      if (result.success) {
        if (result.requirePassword) {
          if (result.isNewUser) {
            // Новый пользователь - переходим к регистрации
            setIsNewUser(true);
            setAuthStep(AuthStep.REGISTER);
          } else {
            // Существующий пользователь - переходим к входу с паролем
            setIsNewUser(false);
            setAuthStep(AuthStep.PASSWORD_LOGIN);
          }
        }
      } else {
        toast({
          variant: "destructive",
          title: "Неверный код",
          description: "Введенный код неверен или истек срок его действия",
        });
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Ошибка проверки кода",
        description: "Не удалось проверить код подтверждения",
      });
    }
  };

  // Обработчик для установки пароля при регистрации
  const handleSetupPassword = async () => {
    try {
      // Валидация пароля
      if (password.length < 6) {
        toast({
          variant: "destructive",
          title: "Слабый пароль",
          description: "Пароль должен содержать минимум 6 символов",
        });
        return;
      }
      
      if (password !== confirmPassword) {
        toast({
          variant: "destructive",
          title: "Пароли не совпадают",
          description: "Введенные пароли не совпадают",
        });
        return;
      }
      
      // Отправляем данные для регистрации
      const success = await setupPassword(phoneNumber, password, firstName, lastName, email);
      
      if (!success) {
        toast({
          variant: "destructive",
          title: "Ошибка регистрации",
          description: "Не удалось завершить регистрацию",
        });
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Ошибка регистрации",
        description: "Не удалось завершить регистрацию",
      });
    }
  };

  // Обработчик для входа с паролем
  const handleLoginWithPassword = async () => {
    try {
      if (password.length < 1) {
        toast({
          variant: "destructive",
          title: "Введите пароль",
          description: "Пожалуйста, введите пароль",
        });
        return;
      }
      
      const success = await loginWithPassword(phoneNumber, password);
      
      if (!success) {
        toast({
          variant: "destructive",
          title: "Ошибка входа",
          description: "Неверный пароль",
        });
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Ошибка входа",
        description: "Не удалось выполнить вход",
      });
    }
  };
  


  // Обработчик выбора страны
  const handleCountrySelect = (country: string, code: string) => {
    setSelectedCountry(country);
    setPhoneNumber(code);
    setShowCountryDropdown(false);
  };

  // Переход на шаг назад
  const handleBack = () => {
    if (authStep === AuthStep.CODE_VERIFICATION) {
      setAuthStep(AuthStep.PHONE_INPUT);
    } else if (authStep === AuthStep.PASSWORD_LOGIN || authStep === AuthStep.REGISTER) {
      setAuthStep(AuthStep.CODE_VERIFICATION);
    }
  };

  // Определяем, какую кнопку показывать в зависимости от шага
  const renderActionButton = () => {
    switch (authStep) {
      case AuthStep.PHONE_INPUT:
        return (
          <Button
            className="w-full bg-[#38A2E1] hover:bg-[#2B90CB] text-white font-medium py-3 rounded-md"
            onClick={handleRequestCode}
            disabled={loading || phoneNumber.length < 5}
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin mr-2" />
            ) : null}
            {t('signin.next')}
          </Button>
        );
      case AuthStep.CODE_VERIFICATION:
        return (
          <Button
            className="w-full bg-[#38A2E1] hover:bg-[#2B90CB] text-white font-medium py-3 rounded-md"
            onClick={handleVerifyCode}
            disabled={loading || verificationCode.length !== 5}
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin mr-2" />
            ) : null}
            {t('signin.verify')}
          </Button>
        );
      case AuthStep.PASSWORD_LOGIN:
        return (
          <Button
            className="w-full bg-[#38A2E1] hover:bg-[#2B90CB] text-white font-medium py-3 rounded-md"
            onClick={handleLoginWithPassword}
            disabled={loading || password.length < 1}
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin mr-2" />
            ) : null}
            {t('signin.login')}
          </Button>
        );
      case AuthStep.REGISTER:
        return (
          <Button
            className="w-full bg-[#38A2E1] hover:bg-[#2B90CB] text-white font-medium py-3 rounded-md"
            onClick={handleSetupPassword}
            disabled={loading || password.length < 6 || password !== confirmPassword}
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin mr-2" />
            ) : null}
            {t('signin.register')}
          </Button>
        );
    }
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
          <h1 className="text-2xl font-bold mb-1 text-center">
            {authStep === AuthStep.PHONE_INPUT && t('signin.title')}
            {authStep === AuthStep.CODE_VERIFICATION && t('signin.verification')}
            {authStep === AuthStep.PASSWORD_LOGIN && t('signin.enter_password')}
            {authStep === AuthStep.REGISTER && t('signin.setup_password')}
          </h1>
          <p className="text-gray-500 text-center text-sm">
            {authStep === AuthStep.PHONE_INPUT && (
              <>
                {t('signin.subtitle')}
                <br />
                {t('signin.phone')}
              </>
            )}
            {authStep === AuthStep.CODE_VERIFICATION && (
              <>
                {t('signin.code_sent')} {phoneNumber}
              </>
            )}
            {authStep === AuthStep.PASSWORD_LOGIN && (
              <>
                {t('signin.password_prompt')}
              </>
            )}
            {authStep === AuthStep.REGISTER && (
              <>
                {t('signin.create_password')}
              </>
            )}
          </p>
        </div>
        
        {/* Кнопка быстрого входа через QR-код */}
        {authStep === AuthStep.PHONE_INPUT && (
          <div className="mb-6 flex justify-center">
            <Button
              variant="outline"
              className="flex items-center gap-2"
              onClick={() => setShowQRCodeModal(true)}
            >
              <QrCode className="h-4 w-4" />
              Быстрый вход через QR-код
            </Button>
          </div>
        )}

        {/* Табы для переключения между обычным входом и входом для админа */}
        <Tabs value={tabValue} onValueChange={setTabValue} className="mb-6">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="phone">{t('signin.user_login')}</TabsTrigger>
            <TabsTrigger value="admin">{t('signin.admin_login')}</TabsTrigger>
          </TabsList>
          
          <TabsContent value="phone" className="mt-4">
            {/* Форма входа */}
            <div className="mb-8">
              {/* Шаг 1: Ввод номера телефона */}
              {authStep === AuthStep.PHONE_INPUT && (
                <>
                  {/* Выбор страны */}
                  <div className="mb-4">
                    <label className="block text-xs text-gray-500 mb-1">{t('signin.country')}</label>
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
                    <label className="block text-xs text-gray-500 mb-1">{t('signin.phone')}</label>
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
                      {t('signin.keep_signed')}
                    </label>
                  </div>
                </>
              )}

              {/* Шаг 2: Верификация кода */}
              {authStep === AuthStep.CODE_VERIFICATION && (
                <div className="mb-6">
                  <label className="block text-xs text-gray-500 mb-3">{t('signin.enter_code')}</label>
                  
                  <div className="my-8">
                    <SecurityCodeInput
                      value={verificationCode}
                      onChange={setVerificationCode}
                      onComplete={handleVerifyCode}
                      disabled={loading}
                    />
                  </div>
                  
                  {/* Информация о коде в Telegram */}
                  <div className="mt-6 mb-2">
                    <div className="flex items-center justify-center bg-blue-50 p-4 rounded-md text-blue-800">
                      <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M19.1025 5.0875L16.955 17.9275C16.7875 18.9038 16.2425 19.13 15.4075 18.67L10.9175 15.32L8.76751 17.3775C8.58751 17.5575 8.43751 17.7075 8.09001 17.7075L8.33251 13.1425L16.3075 5.9875C16.5825 5.7425 16.2475 5.6075 15.8825 5.8525L6.07501 11.9675L1.62501 10.5775C0.665014 10.285 0.647514 9.67 1.83501 9.2275L18.0575 3.1275C18.86 2.835 19.3 3.2925 19.1025 5.0875Z" fill="currentColor"/>
                      </svg>
                      <p className="text-sm">
                        Код подтверждения отправлен в Telegram
                      </p>
                    </div>
                    <p className="text-xs text-gray-500 mt-2 text-center">
                      Проверьте ваши сообщения в Telegram для получения кода подтверждения
                    </p>
                  </div>
                  
                  {/* Кнопка "Отправить код повторно" */}
                  <div className="mt-4 mb-4 text-center">
                    <button
                      className="text-[#38A2E1] text-sm hover:underline"
                      onClick={handleRequestCode}
                      disabled={loading}
                    >
                      {t('signin.resend_code')}
                    </button>
                  </div>
                </div>
              )}

              {/* Шаг 3: Вход с паролем (для существующих пользователей) */}
              {authStep === AuthStep.PASSWORD_LOGIN && (
                <div className="mb-6">
                  <label className="block text-xs text-gray-500 mb-1">{t('signin.password')}</label>
                  <Input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full py-3 px-4 border border-gray-300 rounded-md mb-4"
                  />
                </div>
              )}

              {/* Шаг 4: Регистрация (установка пароля для новых пользователей) */}
              {authStep === AuthStep.REGISTER && (
                <>
                  <div className="mb-4">
                    <label className="block text-xs text-gray-500 mb-1">{t('signin.first_name')}</label>
                    <Input
                      type="text"
                      value={firstName}
                      onChange={(e) => setFirstName(e.target.value)}
                      className="w-full py-3 px-4 border border-gray-300 rounded-md"
                    />
                  </div>
                  
                  <div className="mb-4">
                    <label className="block text-xs text-gray-500 mb-1">{t('signin.last_name')}</label>
                    <Input
                      type="text"
                      value={lastName}
                      onChange={(e) => setLastName(e.target.value)}
                      className="w-full py-3 px-4 border border-gray-300 rounded-md"
                    />
                  </div>
                  
                  <div className="mb-4">
                    <label className="block text-xs text-gray-500 mb-1">{t('signin.email')}</label>
                    <Input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full py-3 px-4 border border-gray-300 rounded-md"
                    />
                  </div>
                  
                  <div className="mb-4">
                    <label className="block text-xs text-gray-500 mb-1">{t('signin.password')}</label>
                    <Input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full py-3 px-4 border border-gray-300 rounded-md"
                    />
                  </div>
                  
                  <div className="mb-6">
                    <label className="block text-xs text-gray-500 mb-1">{t('signin.confirm_password')}</label>
                    <Input
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      className="w-full py-3 px-4 border border-gray-300 rounded-md"
                    />
                    {password !== confirmPassword && confirmPassword && (
                      <p className="text-red-500 text-xs mt-1">{t('signin.passwords_not_match')}</p>
                    )}
                  </div>
                </>
              )}

              {/* Кнопка действия (в зависимости от шага) */}
              {renderActionButton()}
              
              {/* Кнопка "Назад" (показывается на всех шагах кроме первого) */}
              {authStep !== AuthStep.PHONE_INPUT && (
                <button 
                  className="w-full text-[#38A2E1] text-sm mt-4 hover:underline"
                  onClick={handleBack}
                  disabled={loading}
                >
                  {t('signin.back')}
                </button>
              )}
            </div>
          </TabsContent>
          
          <TabsContent value="admin" className="mt-4">
            {/* Перенаправление на страницу входа для админа */}
            <div className="text-center py-8">
              <p className="mb-4 text-gray-600">{t('signin.admin_info')}</p>
              <Button 
                className="bg-[#38A2E1] hover:bg-[#2B90CB] text-white" 
                onClick={() => navigate("/admin-login")}
              >
                {t('signin.go_admin')}
              </Button>
            </div>
          </TabsContent>
        </Tabs>

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
      
      {/* Модальное окно для QR-авторизации */}
      <Dialog open={showQRCodeModal} onOpenChange={setShowQRCodeModal}>
        <DialogContent className="sm:max-w-md p-0 border-none">
          <QRCodeLogin 
            onClose={() => setShowQRCodeModal(false)} 
            onLoginSuccess={handleQRLoginSuccess}
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}
