import { useState, useRef, useEffect } from "react";
import { Chat, Message } from "@/pages/dashboard";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

interface ChatViewProps {
  chat: Chat | null;
  messages: Message[];
  loading: boolean;
}

export default function ChatView({ chat, messages, loading }: ChatViewProps) {
  const [messageText, setMessageText] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  // Прокрутка вниз при загрузке сообщений или выборе нового чата
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, chat]);

  // Группировка сообщений по дате
  const groupedMessages = (messages || []).reduce<Record<string, Message[]>>(
    (groups, message) => {
      const date = new Date(message.timestamp).toLocaleDateString("ru-RU");
      if (!groups[date]) {
        groups[date] = [];
      }
      groups[date].push(message);
      return groups;
    },
    {}
  );

  // Обработчик отправки сообщения
  const handleSendMessage = () => {
    // В будущем здесь будет логика отправки сообщения через API
    setMessageText("");
  };

  // Обработчик нажатия клавиши Enter
  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && messageText.trim()) {
      handleSendMessage();
    }
  };

  // Отображение пустого состояния, если нет выбранного чата
  if (!chat) {
    return (
      <Card className="h-full flex flex-col">
        <CardContent className="p-0 flex-grow flex items-center justify-center">
          <div className="text-center p-6">
            <span className="material-icons text-4xl text-neutral-gray mb-4">
              chat_bubble_outline
            </span>
            <h3 className="text-lg font-medium text-neutral-dark mb-2">
              Выберите чат
            </h3>
            <p className="text-neutral-gray">
              Выберите чат из списка слева, чтобы начать общение
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  // Отображение состояния загрузки
  if (loading) {
    return (
      <Card className="h-full flex flex-col">
        <div className="p-4 bg-telegram-light border-b border-gray-200 flex items-center">
          <Skeleton className="w-10 h-10 rounded-full mr-3" />
          <div>
            <Skeleton className="h-5 w-32 mb-1" />
            <Skeleton className="h-3 w-20" />
          </div>
        </div>
        <CardContent className="p-4 flex-grow bg-[#e5ddd5] bg-opacity-30">
          {Array(3)
            .fill(0)
            .map((_, i) => (
              <div
                key={i}
                className={`mb-4 flex ${i % 2 === 0 ? "" : "justify-end"}`}
              >
                {i % 2 === 0 && <Skeleton className="w-8 h-8 rounded-full mr-2 self-end" />}
                <div
                  className={`max-w-xs md:max-w-md rounded-lg p-3 shadow ${
                    i % 2 === 0 ? "bg-white" : "bg-telegram-light"
                  }`}
                >
                  <Skeleton className="h-4 w-48 mb-1" />
                  <Skeleton className="h-4 w-32 mb-1" />
                  <Skeleton className="h-4 w-40" />
                  <div className="mt-1 flex justify-end">
                    <Skeleton className="h-3 w-10" />
                  </div>
                </div>
              </div>
            ))}
        </CardContent>
        <div className="p-3 border-t border-gray-200 bg-white">
          <div className="flex items-center">
            <Skeleton className="w-8 h-8 rounded-full mr-2" />
            <Skeleton className="flex-grow h-10 rounded-full mx-2" />
            <Skeleton className="w-8 h-8 rounded-full mr-1" />
            <Skeleton className="w-8 h-8 rounded-full" />
          </div>
        </div>
      </Card>
    );
  }

  return (
    <Card className="h-full flex flex-col">
      {/* Заголовок чата */}
      <div className="p-4 bg-telegram-light border-b border-gray-200 flex items-center">
        <div className="flex items-center flex-grow">
          {chat.avatarUrl ? (
            <img
              src={chat.avatarUrl}
              alt={`Аватар ${chat.title}`}
              className="w-10 h-10 rounded-full mr-3"
            />
          ) : (
            <div className="w-10 h-10 rounded-full bg-telegram-blue flex items-center justify-center mr-3">
              <span className="material-icons text-white">
                {chat.type === "private" ? "person" : "group"}
              </span>
            </div>
          )}
          <div>
            <h2 className="font-medium">{chat.title}</h2>
            <p className="text-xs text-neutral-gray">
              {chat.isOnline ? "В сети" : "Не в сети"}
            </p>
          </div>
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="rounded-full"
        >
          <span className="material-icons text-neutral-gray">more_vert</span>
        </Button>
      </div>

      {/* Сообщения */}
      <ScrollArea 
        className="flex-grow p-4 bg-[#e5ddd5] bg-opacity-30" 
        style={{ height: "450px" }}
        ref={scrollRef}
      >
        {Object.keys(groupedMessages).length > 0 ? (
          Object.entries(groupedMessages).map(([date, dayMessages]) => (
            <div key={date}>
              {/* Маркер даты */}
              <div className="flex justify-center mb-4">
                <span className="inline-block bg-white bg-opacity-70 text-xs text-neutral-gray px-3 py-1 rounded-full">
                  {date}
                </span>
              </div>

              {/* Сообщения дня */}
              {dayMessages.map((message) => (
                <div
                  key={message.id}
                  className={`mb-4 flex ${
                    message.isIncoming ? "" : "justify-end"
                  }`}
                >
                  {message.isIncoming && (
                    <div className="w-8 h-8 rounded-full bg-telegram-light flex items-center justify-center mr-2 self-end">
                      <span className="material-icons text-telegram-blue text-sm">
                        person
                      </span>
                    </div>
                  )}
                  <div
                    className={`max-w-xs md:max-w-md rounded-lg p-3 shadow ${
                      message.isIncoming ? "bg-white" : "bg-telegram-light"
                    }`}
                  >
                    {message.text && <p className="text-sm">{message.text}</p>}
                    
                    {message.mediaType === "image" && message.mediaUrl && (
                      <img
                        src={message.mediaUrl}
                        alt="Изображение из сообщения"
                        className="w-full h-auto rounded-md mb-2"
                      />
                    )}
                    
                    {message.mediaType === "voice" && (
                      <div className="flex items-center">
                        <button className="p-1 bg-telegram-blue rounded-full text-white mr-2">
                          <span className="material-icons" style={{ fontSize: "18px" }}>
                            play_arrow
                          </span>
                        </button>
                        <div className="flex-grow">
                          <div className="h-1 bg-gray-200 rounded">
                            <div className="h-1 bg-telegram-blue rounded" style={{ width: "30%" }}></div>
                          </div>
                          <span className="text-xs text-neutral-gray">0:24</span>
                        </div>
                      </div>
                    )}
                    
                    <div className="mt-1 flex justify-end">
                      <span className="text-xs text-neutral-gray">
                        {new Date(message.timestamp).toLocaleTimeString("ru-RU", {
                          hour: "2-digit",
                          minute: "2-digit",
                        })}
                      </span>
                      {!message.isIncoming && (
                        <span className="material-icons text-xs text-telegram-blue ml-1">
                          done_all
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ))
        ) : (
          <div className="flex flex-col items-center justify-center h-full">
            <span className="material-icons text-4xl text-neutral-gray mb-4">
              forum
            </span>
            <p className="text-neutral-gray text-center">
              Здесь будут отображаться сообщения чата
            </p>
          </div>
        )}
      </ScrollArea>

      {/* Поле ввода сообщения */}
      <div className="p-3 border-t border-gray-200 bg-white">
        <div className="flex items-center">
          <Button
            variant="ghost"
            size="sm"
            className="rounded-full"
          >
            <span className="material-icons text-neutral-gray">attach_file</span>
          </Button>
          <div className="flex-grow mx-2">
            <Input
              type="text"
              placeholder="Написать сообщение..."
              className="w-full py-2 px-3 border border-gray-300 rounded-full focus:outline-none focus:border-telegram-blue"
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
              onKeyDown={handleKeyPress}
            />
          </div>
          <Button
            variant="ghost"
            size="sm"
            className="rounded-full mr-1"
          >
            <span className="material-icons text-neutral-gray">mic</span>
          </Button>
          <Button
            variant="default"
            size="sm"
            className="rounded-full bg-telegram-blue hover:bg-telegram-dark"
            onClick={handleSendMessage}
            disabled={!messageText.trim()}
          >
            <span className="material-icons">send</span>
          </Button>
        </div>
      </div>
    </Card>
  );
}
