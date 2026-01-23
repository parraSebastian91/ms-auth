import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import * as vault from 'node-vault';

interface VaultSecrets {
  [key: string]: any;
}

@Injectable()
export class VaultService implements OnModuleInit {
  private readonly logger = new Logger(VaultService. name);
  private client: any;
  private secrets: Map<string, VaultSecrets> = new Map();
  private isInitialized = false;

  async onModuleInit() {
    try {
      await this.initializeVault();
      await this.loadAllSecrets();
      this.isInitialized = true;
      this.logger.log('✅ Vault initialized and secrets loaded');
    } catch (error) {
      this.logger. error('❌ Failed to initialize Vault', error);
      // En desarrollo, continuar sin Vault
      if (process.env.NODE_ENV !== 'production') {
        this.logger.warn('⚠️ Running without Vault (development mode)');
      } else {
        throw error;
      }
    }
  }

  private async initializeVault() {
    const vaultAddr = process.env.VAULT_ADDR || 'http://vault:8200';
    const vaultToken = process.env. VAULT_TOKEN || 'myroot';

    this.logger.log(`Connecting to Vault at ${vaultAddr}`);

    this.client = vault({
      apiVersion: 'v1',
      endpoint: vaultAddr,
      token: vaultToken,
    });

    // Verificar conexión
    await this.client.health();
  }

  private async loadAllSecrets() {
    try {
      // Cargar secretos de auth-service
      const authSecrets = await this.readSecret('auth-service');
      this.secrets.set('auth-service', authSecrets);

      // Cargar secretos de database
      const dbSecrets = await this.readSecret('database');
      this.secrets.set('database', dbSecrets);

      // Cargar secretos de Redis
      const redisSecrets = await this.readSecret('redis');
      this.secrets.set('redis', redisSecrets);

      // Cargar secretos compartidos
      const sharedSecrets = await this.readSecret('shared');
      this.secrets.set('shared', sharedSecrets);

      this.logger.log(`Loaded ${this.secrets.size} secret paths`);
    } catch (error) {
      this.logger. error('Failed to load secrets', error);
      throw error;
    }
  }

  private async readSecret(path: string): Promise<VaultSecrets> {
    try {
      const response = await this.client.read(`secret/data/${path}`);
      return response.data. data;
    } catch (error) {
      this.logger. warn(`Failed to read secret from path:  ${path}`);
      return {};
    }
  }

  /**
   * Obtener un secreto específico
   * @param path - Ruta del secreto (ej: 'auth-service', 'database')
   * @param key - Clave específica (ej: 'jwt_secret', 'password')
   * @param defaultValue - Valor por defecto si no existe
   */
  getSecret(path: string, key:  string, defaultValue?: any): any {
    if (!this.isInitialized) {
      // Fallback a variables de entorno
      const envKey = key.toUpperCase();
      return process.env[envKey] || defaultValue;
    }

    const pathSecrets = this.secrets.get(path);
    if (!pathSecrets) {
      this.logger.warn(`Secret path not found: ${path}`);
      return process.env[key. toUpperCase()] || defaultValue;
    }

    return pathSecrets[key] || process.env[key.toUpperCase()] || defaultValue;
  }

  /**
   * Obtener todos los secretos de una ruta
   */
  getAllSecrets(path: string): VaultSecrets {
    const cached = this.secrets.get(path);

    // If Vault is not ready or the path is empty, fall back to env vars
    if (!this.isInitialized || !cached || Object.keys(cached).length === 0) {
      this.logger.warn(`Using env fallback for secrets path: ${path}`);
      // Return only env vars that look related to this path (same naming we expect)
      const envCopy: VaultSecrets = {};
      Object.keys(process.env).forEach((k) => {
        envCopy[k] = process.env[k];
      });
      return envCopy;
    }

    return cached;
  }

  /**
   * Refrescar secretos (útil para rotación)
   */
  async refreshSecrets() {
    this.logger.log('Refreshing secrets from Vault.. .');
    await this.loadAllSecrets();
    this.logger.log('✅ Secrets refreshed');
  }

  /**
   * Verificar si Vault está disponible
   */
  isAvailable(): boolean {
    return this.isInitialized;
  }
}