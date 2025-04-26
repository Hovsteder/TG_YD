import { config } from 'dotenv';
config(); // Загружаем .env до всего остального

import { Pool, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/node-postgres';
import ws from "ws";
import * as schema from "@shared/schema";
import pg from 'pg';
import type { Pool as PgPoolType } from 'pg';

neonConfig.webSocketConstructor = ws;

let pool: PgPoolType | null = null;

function getPool(): PgPoolType {
  if (!pool) {
    if (!process.env.DATABASE_URL) {
      throw new Error(
        "DATABASE_URL must be set. Did you forget to provision a database?",
      );
    }
    pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
    console.log("Database pool created.");
  }
  return pool;
}

export const db = drizzle(getPool(), { schema });
