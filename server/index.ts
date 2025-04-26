import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { initTelegramAuth, cleanupExpiredQrSessions, safeStringify } from "./telegram-gram";
import { DatabaseStorage, type IStorage } from "./storage";
import { db } from "./db";

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        try {
          // Сжимаем большие объекты для логирования
          const compressForLogging = (obj: any): any => {
            if (!obj || typeof obj !== 'object') return obj;
            
            // Если это массив
            if (Array.isArray(obj)) {
              if (obj.length <= 3) {
                return obj.map(item => compressForLogging(item));
              } else {
                return [
                  compressForLogging(obj[0]), 
                  `... ${obj.length - 2} more items ...`, 
                  compressForLogging(obj[obj.length - 1])
                ];
              }
            }
            
            // Если это объект
            const keys = Object.keys(obj);
            if (keys.length <= 5) {
              const result = {};
              for (const key of keys) {
                result[key] = compressForLogging(obj[key]);
              }
              return result;
            } else {
              const result = {};
              // Добавляем первые 3 ключа
              for (let i = 0; i < 3; i++) {
                if (i < keys.length) {
                  result[keys[i]] = compressForLogging(obj[keys[i]]);
                }
              }
              result['...'] = `${keys.length - 3} more properties`;
              return result;
            }
          };
          
          // Сжимаем объект перед сериализацией, если он слишком большой
          const loggingObj = Object.keys(capturedJsonResponse).length > 5 
                           ? compressForLogging(capturedJsonResponse) 
                           : capturedJsonResponse;
          
          const shortenedJson = safeStringify(loggingObj);
          logLine += ` :: ${shortenedJson}`;
        } catch (error) {
          logLine += ` :: [JSON serialization error: ${error.message}]`;
        }
      }

      if (logLine.length > 120) {
        logLine = logLine.slice(0, 117) + "...";
      }

      log(logLine);
    }
  });

  next();
});

(async () => {
  // Создаем экземпляр storage здесь, чтобы передать его
  const storage: IStorage = new DatabaseStorage();

  // Инициализация Telegram Auth (возвращаем вызов)
  await initTelegramAuth(db);
  
  // Запускаем очистку старых QR сессий при старте и затем периодически
  // Передаем storage в функцию
  cleanupExpiredQrSessions(storage);
  setInterval(() => cleanupExpiredQrSessions(storage), 5 * 60 * 1000);
  
  // Передаем storage в registerRoutes
  const server = await registerRoutes(app);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    res.status(status).json({ message });
    throw err;
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // Определение порта из переменной окружения или использование 5000 по умолчанию
  // Это позволяет настраивать порт без изменения кода
  const port = parseInt(process.env.PORT || "5000", 10);
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true,
  }, () => {
    log(`serving on port ${port}`);
  });
})();
