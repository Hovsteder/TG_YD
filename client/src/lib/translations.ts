type TranslationKey = {
  en: string;
  ru: string;
};

export const translations: Record<string, TranslationKey> = {
  // Аутентификация
  login: {
    en: "Login",
    ru: "Вход"
  },
  register: {
    en: "Register",
    ru: "Регистрация"
  },
  phone_number: {
    en: "Phone Number",
    ru: "Номер телефона"
  },
  send_code: {
    en: "Send Code",
    ru: "Отправить код"
  },
  verification_code: {
    en: "Verification Code",
    ru: "Код подтверждения"
  },
  verify: {
    en: "Verify",
    ru: "Подтвердить"
  },
  password: {
    en: "Password",
    ru: "Пароль"
  },
  confirm_password: {
    en: "Confirm Password",
    ru: "Подтвердите пароль"
  },
  first_name: {
    en: "First Name",
    ru: "Имя"
  },
  last_name: {
    en: "Last Name",
    ru: "Фамилия"
  },
  email: {
    en: "Email",
    ru: "Email"
  },
  create_account: {
    en: "Create Account",
    ru: "Создать аккаунт"
  },
  logout: {
    en: "Logout",
    ru: "Выйти"
  },
  submit: {
    en: "Submit",
    ru: "Отправить"
  },
  
  // Страница авторизации
  "signin.title": {
    en: "Sign In",
    ru: "Вход в систему"
  },
  "signin.subtitle": {
    en: "Welcome back",
    ru: "Добро пожаловать"
  },
  "signin.phone": {
    en: "Please enter your phone number",
    ru: "Пожалуйста, введите ваш номер телефона"
  },
  "signin.country": {
    en: "Country",
    ru: "Страна"
  },
  "signin.next": {
    en: "Next",
    ru: "Далее"
  },
  "signin.user_login": {
    en: "User Login",
    ru: "Вход пользователя"
  },
  "signin.admin_login": {
    en: "Admin Login",
    ru: "Вход администратора"
  },
  "signin.verification": {
    en: "Verification",
    ru: "Подтверждение"
  },
  "signin.code_sent": {
    en: "Code sent to",
    ru: "Код отправлен на"
  },
  "signin.enter_code": {
    en: "Enter verification code",
    ru: "Введите код подтверждения"
  },
  "signin.resend_code": {
    en: "Resend code",
    ru: "Отправить код повторно"
  },
  "signin.verify": {
    en: "Verify",
    ru: "Подтвердить"
  },
  "signin.back": {
    en: "Back",
    ru: "Назад"
  },
  "signin.keep_signed": {
    en: "Keep me signed in",
    ru: "Оставаться в системе"
  },
  "signin.enter_password": {
    en: "Enter Password",
    ru: "Введите пароль"
  },
  "signin.password_prompt": {
    en: "Please enter your password to login",
    ru: "Пожалуйста, введите пароль для входа"
  },
  "signin.login": {
    en: "Login",
    ru: "Войти"
  },
  "signin.setup_password": {
    en: "Setup Password",
    ru: "Создание пароля"
  },
  "signin.create_password": {
    en: "Create a password for your account",
    ru: "Создайте пароль для вашей учетной записи"
  },
  "signin.passwords_not_match": {
    en: "Passwords do not match",
    ru: "Пароли не совпадают"
  },
  "signin.register": {
    en: "Register",
    ru: "Зарегистрироваться"
  },
  "signin.admin_info": {
    en: "This section is for administrators only",
    ru: "Этот раздел только для администраторов"
  },
  "signin.go_admin": {
    en: "Go to admin login",
    ru: "Перейти к входу администратора"
  },
  
  // QR-код авторизации
  "qr.login": {
    en: "Login with QR Code",
    ru: "Войти через QR-код"
  },
  "qr.title": {
    en: "Login with QR Code",
    ru: "Войти через QR-код"
  }, 
  "qr.description": {
    en: "Scan the QR code in the Telegram app for quick login",
    ru: "Отсканируйте QR-код в приложении Telegram для быстрого входа"
  },
  "qr.loading": {
    en: "Loading QR code...",
    ru: "Загрузка QR-кода..."
  },
  "qr.failed": {
    en: "Failed to load QR code",
    ru: "Не удалось загрузить QR-код"
  },
  "qr.time_left": {
    en: "Time left",
    ru: "Осталось времени"
  },
  "qr.valid_for": {
    en: "QR code is valid for",
    ru: "QR-код действителен в течение"
  },
  "qr.minutes": {
    en: "minutes",
    ru: "минут"
  },
  "qr.waiting": {
    en: "Waiting for scan...",
    ru: "Ожидание сканирования..."
  },
  "qr.refresh": {
    en: "Refresh QR Code",
    ru: "Обновить QR-код"
  },
  
  // Чаты и сообщения
  your_chats: {
    en: "Your Chats",
    ru: "Ваши чаты"
  },
  logged_in_as: {
    en: "Logged in as",
    ru: "Вы вошли как"
  },
  recent_chats: {
    en: "Recent Chats",
    ru: "Недавние чаты"
  },
  no_chats_found: {
    en: "No chats found",
    ru: "Чаты не найдены"
  },
  no_chats_description: {
    en: "Your recent chats will appear here",
    ru: "Ваши недавние чаты появятся здесь"
  },
  private_chat: {
    en: "Private Chat",
    ru: "Личный чат"
  },
  group: {
    en: "Group",
    ru: "Группа"
  },
  channel: {
    en: "Channel",
    ru: "Канал"
  },
  no_messages: {
    en: "No messages",
    ru: "Нет сообщений"
  },
  start_conversation: {
    en: "Start a conversation now",
    ru: "Начните беседу прямо сейчас"
  },
  type_message: {
    en: "Type a message...",
    ru: "Введите сообщение..."
  },
  select_chat: {
    en: "Select a chat",
    ru: "Выберите чат"
  },
  select_chat_description: {
    en: "Choose a conversation from the list to view messages",
    ru: "Выберите беседу из списка, чтобы просмотреть сообщения"
  },
  unknown: {
    en: "Unknown",
    ru: "Неизвестно"
  },
  message_sent: {
    en: "Message sent",
    ru: "Сообщение отправлено"
  },
  message_sent_description: {
    en: "Your message has been sent successfully",
    ru: "Ваше сообщение успешно отправлено"
  },
  error_loading_chats: {
    en: "Error loading chats",
    ru: "Ошибка загрузки чатов"
  },
  error_loading_chats_description: {
    en: "Could not load your chats. Please try again later",
    ru: "Не удалось загрузить ваши чаты. Пожалуйста, попробуйте позже"
  },
  error_loading_messages: {
    en: "Error loading messages",
    ru: "Ошибка загрузки сообщений"
  },
  error_loading_messages_description: {
    en: "Could not load messages. Please try again later",
    ru: "Не удалось загрузить сообщения. Пожалуйста, попробуйте позже"
  },
  
  // Статус авторизации
  not_authenticated: {
    en: "Not authenticated",
    ru: "Вы не авторизованы"
  },
  please_login: {
    en: "Please login to view your chats",
    ru: "Пожалуйста, войдите, чтобы просмотреть ваши чаты"
  },
  
  // Общие
  loading: {
    en: "Loading...",
    ru: "Загрузка..."
  },
  error: {
    en: "Error",
    ru: "Ошибка"
  },
  success: {
    en: "Success",
    ru: "Успешно"
  },
  cancel: {
    en: "Cancel",
    ru: "Отмена"
  },
  save: {
    en: "Save",
    ru: "Сохранить"
  },
  delete: {
    en: "Delete",
    ru: "Удалить"
  },
  settings: {
    en: "Settings",
    ru: "Настройки"
  },
  profile: {
    en: "Profile",
    ru: "Профиль"
  },
  
  // Админ-панель
  admin_panel: {
    en: "Admin Panel",
    ru: "Панель администратора"
  },
  dashboard: {
    en: "Dashboard",
    ru: "Дашборд"
  },
  users: {
    en: "Users",
    ru: "Пользователи"
  },
  sessions: {
    en: "Sessions",
    ru: "Сессии"
  },
  system_logs: {
    en: "System Logs",
    ru: "Системные логи"
  },
  telegram_settings: {
    en: "Telegram Settings",
    ru: "Настройки Telegram"
  },
};