import { registerAs } from "@nestjs/config";


export default registerAs('database', () => ({
   type: 'postgres',
    host: process.env.DATABASE_HOST || 'localhost',
    port: parseInt(process.env.DATABASE_PORT, 10) || 5432,
    username: process.env.DATABASE_USER || 'postgres',
    password: process.env.DATABASE_PASSWORD || 'desarrollo123',
    database: process.env.DATABASE_NAME || 'postgres',
    schema: 'core',
    synchronize: true,
}));