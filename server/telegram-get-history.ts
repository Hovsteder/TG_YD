import { TelegramClient } from "telegram";
import { Api } from "telegram";

// Импортируем готовый экземпляр клиента
import { getClient } from "./telegram-gram";

export async function getChatHistory(peer: any, limit = 20): Promise<any> {
  try {
    // Получаем клиент Telegram
    const currentClient = await getClient();
    
    if (!currentClient || !currentClient.connected) {
      console.error("Failed to get connected Telegram client");
      return {
        success: false,
        error: "Not connected to Telegram API"
      };
    }
    
    console.log(`Fetching chat history with peer:`, peer);
    
    // Формируем правильный InputPeer для API запроса
    let inputPeer = null;
    
    if (peer._ === 'inputPeerUser') {
      // Для пользователя
      inputPeer = {
        _: 'inputPeerUser',
        user_id: parseInt(peer.user_id),
        access_hash: peer.access_hash
      };
    } else if (peer._ === 'inputPeerChat') {
      // Для обычного чата
      inputPeer = {
        _: 'inputPeerChat',
        chat_id: parseInt(peer.chat_id)
      };
    } else if (peer._ === 'inputPeerChannel') {
      // Для канала или супергруппы
      inputPeer = {
        _: 'inputPeerChannel',
        channel_id: parseInt(peer.channel_id),
        access_hash: peer.access_hash
      };
    }
    
    if (!inputPeer) {
      throw new Error(`Unsupported peer type: ${peer._}`);
    }
    
    console.log("Using getHistory API with peer:", JSON.stringify(inputPeer));
    
    // Вызываем GetHistory напрямую через API
    try {
      const result = await currentClient.invoke(new Api.messages.GetHistory({
        peer: inputPeer,
        offsetId: 0,
        offsetDate: 0,
        addOffset: 0,
        limit: limit,
        maxId: 0,
        minId: 0,
        hash: BigInt(0)
      }));
      
      console.log("GetHistory response received");
      
      if (result && result.messages) {
        // Форматируем результат
        const messages = result.messages;
        const users = result.users || [];
        
        console.log(`Retrieved ${messages.length} messages, ${users.length} users`);
        
        // Форматируем сообщения
        const formattedMessages = messages.map((msg: any) => {
          // Определяем отправителя
          let from_id = null;
          if (msg.fromId) {
            from_id = msg.fromId;
          }
          
          return {
            _: 'message',
            id: msg.id, 
            message: msg.message || '',
            date: msg.date,
            out: msg.out || false,
            media: msg.media || null,
            from_id: from_id
          };
        });
        
        return {
          success: true,
          messages: formattedMessages,
          users: users
        };
      } else {
        return {
          success: false,
          error: "No messages returned from API"
        };
      }
    } catch (historyError) {
      console.error("Error with getHistory request:", historyError);
      return {
        success: false,
        error: "Error fetching message history: " + historyError.message
      };
    }
  } catch (error: any) {
    console.error("Error in getChatHistory:", error);
    return {
      success: false,
      error: error.message || "Error connecting to Telegram API"
    };
  }
}