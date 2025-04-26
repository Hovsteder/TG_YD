import { useState, useRef, useEffect } from "react";
import { Input } from "@/components/ui/input";

interface SecurityCodeInputProps {
  value: string;
  onChange: (value: string) => void;
  onComplete?: () => void;
  disabled?: boolean;
}

export default function SecurityCodeInput({
  value,
  onChange,
  onComplete,
  disabled = false
}: SecurityCodeInputProps) {
  const [inputs, setInputs] = useState<string[]>(Array(5).fill(""));
  const inputRefs = useRef<(HTMLInputElement | null)[]>(Array(5).fill(null));

  // Синхронизация входящего значения с состоянием
  useEffect(() => {
    const chars = value.split("").slice(0, 5);
    setInputs([...chars, ...Array(5 - chars.length).fill("")]);
  }, [value]);

  // Обработка изменения отдельных полей
  const handleInputChange = (index: number, char: string) => {
    // Проверяем, что введен только один символ-цифра
    if (!/^\d?$/.test(char)) return;

    const newInputs = [...inputs];
    newInputs[index] = char;
    setInputs(newInputs);

    // Обновляем значение для родителя
    onChange(newInputs.join(""));

    // Перемещаем фокус на следующее поле
    if (char && index < 5) {
      inputRefs.current[index + 1]?.focus();
    }

    // Вызываем onComplete, если все поля заполнены
    if (newInputs.filter(Boolean).length === 6 && onComplete) {
      onComplete();
    }
  };

  // Обработка нажатия клавиш
  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    // Перемещение назад при нажатии Backspace
    if (e.key === "Backspace" && !inputs[index] && index > 0) {
      inputRefs.current[index - 1]?.focus();
    }
    
    // Навигация стрелками
    if (e.key === "ArrowLeft" && index > 0) {
      e.preventDefault();
      inputRefs.current[index - 1]?.focus();
    }
    
    if (e.key === "ArrowRight" && index < 5) {
      e.preventDefault();
      inputRefs.current[index + 1]?.focus();
    }
  };

  // Обработка вставки текста
  const handlePaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData("text").trim();
    
    // Проверяем, что вставлены только цифры
    if (!/^\d+$/.test(pastedData)) return;
    
    // Создаем массив из вставленных символов (не более 6)
    const chars = pastedData.split("").slice(0, 6);
    const newInputs = [...Array(6).fill("")];
    
    // Заполняем inputs вставленными символами
    chars.forEach((char, i) => {
      if (i < 6) newInputs[i] = char;
    });
    
    setInputs(newInputs);
    onChange(newInputs.join(""));
    
    // Фокусируемся на последнем поле или следующем пустом
    const nextEmptyIndex = newInputs.findIndex(val => !val);
    if (nextEmptyIndex !== -1) {
      inputRefs.current[nextEmptyIndex]?.focus();
    } else {
      inputRefs.current[5]?.focus();
    }
    
    // Вызываем onComplete, если все поля заполнены
    if (newInputs.filter(Boolean).length === 6 && onComplete) {
      onComplete();
    }
  };

  return (
    <div className="flex justify-between">
      {inputs.map((digit, index) => (
        <Input
          key={index}
          ref={el => inputRefs.current[index] = el}
          type="text"
          inputMode="numeric"
          pattern="\d*"
          maxLength={1}
          value={digit}
          onChange={e => handleInputChange(index, e.target.value)}
          onKeyDown={e => handleKeyDown(index, e)}
          onPaste={index === 0 ? handlePaste : undefined}
          disabled={disabled}
          className="w-12 h-14 text-center text-2xl font-medium border rounded-md mx-1 focus:border-telegram-blue focus:outline-none disabled:opacity-70"
        />
      ))}
    </div>
  );
}
