import { QueryClient, QueryFunction } from "@tanstack/react-query";

async function throwIfResNotOk(res: Response) {
  if (!res.ok) {
    const text = (await res.text()) || res.statusText;
    throw new Error(`${res.status}: ${text}`);
  }
}

export async function apiRequest(
  method: string,
  url: string,
  data?: unknown | undefined,
  headers?: Record<string, string>,
): Promise<Response> {
  const defaultHeaders: Record<string, string> = data 
    ? { "Content-Type": "application/json" } 
    : {};
  
  // Добавляем токен авторизации из localStorage, если он существует
  const sessionToken = localStorage.getItem("sessionToken");
  if (sessionToken) {
    defaultHeaders["Authorization"] = `Bearer ${sessionToken}`;
  }
    
  const requestHeaders = headers 
    ? { ...defaultHeaders, ...headers } 
    : defaultHeaders;
    
  console.log("API Request:", { method, url, headers: requestHeaders });
    
  const res = await fetch(url, {
    method,
    headers: requestHeaders,
    body: data ? JSON.stringify(data) : undefined,
    credentials: "include",
  });

  await throwIfResNotOk(res);
  return res;
}

type UnauthorizedBehavior = "returnNull" | "throw";
export const getQueryFn: <T>(options: {
  on401: UnauthorizedBehavior;
}) => QueryFunction<T> =
  ({ on401: unauthorizedBehavior }) =>
  async ({ queryKey, meta }) => {
    // Извлекаем заголовки из meta, если они есть
    const headers = meta?.headers ? { ...meta.headers } : {};
    
    const res = await fetch(queryKey[0] as string, {
      headers,
      credentials: "include",
    });

    if (unauthorizedBehavior === "returnNull" && res.status === 401) {
      return null;
    }

    await throwIfResNotOk(res);
    return await res.json();
  };

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      queryFn: getQueryFn({ on401: "throw" }),
      refetchInterval: false,
      refetchOnWindowFocus: false,
      staleTime: Infinity,
      retry: false,
    },
    mutations: {
      retry: false,
    },
  },
});
