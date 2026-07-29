
export default () => ({
  app: {
    port: parseInt(process.env.PORT, 10),
    ttlAuthCode: parseInt(process.env.TTL_AUTH_CODE ?? '60', 10) * 1000, // 1 minutos por defecto
    ttlSession: parseInt(process.env.TTL_SESSION ?? '3600', 10) * 1000, // 1 hora por defecto
    ttlRefreshSession: parseInt(process.env.JWT_REFRESH_EXPIRES_IN ?? '86400', 10) * 1000, // 1 día por defecto
  },
  database: {
    type: 'postgres',
    host: process.env.DATABASE_HOST,
    port: parseInt(process.env.DATABASE_PORT, 10),
    database: process.env.DATABASE_NAME,
    username: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    schema: process.env.DATABASE_SCHEMA,
    ssl: process.env.DATABASE_SSL === 'true',
  },
  redis: {
    host: process.env.REDIS_HOST ,
    port: parseInt(process.env.REDIS_PORT, 10) || 6379,
    ttl: parseInt(process.env.REDIS_TTL, 10) * 1000 || 3600 * 1000, // 1 hora por defecto
  },
  vault: {
    addr: process.env.VAULT_ADDR,
    token: process.env.VAULT_TOKEN,
  },
  jwtConfig: {
    refresh_secret: process.env.JWT_REFRESH_SECRET,
    refresh_expires_in: process.env.JWT_REFRESH_EXPIRES_IN,
    access_secret: process.env.JWT_ACCESS_SECRET,
    access_expires_in: process.env.JWT_ACCESS_EXPIRES_IN,
    admin_expires_in: process.env.JWT_ACCESS_ADMIN_EXPIRES_IN,
  }
});

