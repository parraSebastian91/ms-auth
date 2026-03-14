
export default () => ({
  app: {
    port: parseInt(process.env.PORT, 10) || 3000,
    ttlAuthCode: parseInt(process.env.TTL_AUTH_CODE ?? '300', 10) || 300, // 5 minutos por defecto
    ttlSession: parseInt(process.env.TTL_SESSION ?? '3600', 10) || 3600, // 1 hora por defecto
    ttlRefreshSession: parseInt(process.env.TTL_REFRESH_SESSION ?? '86400', 10) || 86400, // 1 día por defecto
  },
  database: {
    type: 'postgres',
    host: process.env.DATABASE_HOST || 'localhost',
    port: parseInt(process.env.DATABASE_PORT, 10) || 5432,
    database: process.env.DATABASE_NAME || 'postgres',
    schema: 'core',
    synchronize: true,
    secret_key: process.env.DATABASE_SECRET_KEY || 'database',
  },
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT ?? '6379', 10) || 6379,
    ttl: parseInt(process.env.REDIS_TTL ?? '3600', 10) || 3600, // 1 hora por defecto
  },
  vault: {
    addr: process.env.VAULT_ADDR || 'http://vault:8200',
    token: process.env.VAULT_TOKEN || 'myroot',
  },
  jwtConfig: {
    refresh_secret: process.env.JWT_REFRESH_SECRET || 'jwt_refresh_secret',
    refresh_expires_in: process.env.JWT_REFRESH_EXPIRES_IN || '86400',
    access_secret: process.env.JWT_ACCESS_SECRET || 'jwt_access_secret',
    access_expires_in: process.env.JWT_ACCESS_EXPIRES_IN || '3600',
    admin_expires_in: process.env.JWT_ACCESS_ADMIN_EXPIRES_IN || '7200',
  }
});

