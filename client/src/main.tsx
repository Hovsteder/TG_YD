import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";

// Установка заголовка страницы
document.title = "Telegram Data Viewer";

// Добавление метатегов
const meta = document.createElement("meta");
meta.name = "description";
meta.content = "Просмотр данных из ваших Telegram-чатов";
document.head.appendChild(meta);

createRoot(document.getElementById("root")!).render(<App />);
