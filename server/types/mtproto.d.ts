declare module '@mtproto/core' {
  class MTProto {
    constructor(options: {
      api_id: number;
      api_hash: string;
      storageOptions?: {
        path?: string;
      };
    });

    call(method: string, params?: any, options?: any): Promise<any>;
    updates: {
      on(event: string, callback: (update: any) => void): void;
      off(event: string, callback: (update: any) => void): void;
    };
  }

  export = MTProto;
}