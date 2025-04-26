export interface IStorage {
  getQrSessionBySessionToken(sessionToken: string): Promise<IQrSession | null>;
  getQrSessionByLoginToken(loginToken: string): Promise<IQrSession | null>;
  setQrSession(session: IQrSession): Promise<string>;
  getQrSessions(): Promise<IQrSession[]>;
  deleteQrSession(sessionToken: string): Promise<void>;
  deleteExpiredQrSessions(): Promise<void>;
}

export class PostgresStorage implements IStorage {
  private pool: any;

  constructor(pool: any) {
    this.pool = pool;
  }

  async deleteQrSession(sessionToken: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const query = `DELETE FROM qr_sessions WHERE session_token = $1`;
      this.pool.query(query, [sessionToken], (err) => {
        if (err) {
          console.error('Error deleting QR session:', err);
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }

  async deleteExpiredQrSessions(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const query = `DELETE FROM qr_sessions WHERE created_at < NOW() - INTERVAL '1 hour'`;
      this.pool.query(query, [], (err, result) => {
        if (err) {
          console.error('Error deleting expired QR sessions:', err);
          reject(err);
        } else {
          console.log(`Deleted ${result.rowCount} expired QR sessions`);
          resolve();
        }
      });
    });
  }
} 