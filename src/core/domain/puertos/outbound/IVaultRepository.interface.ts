export interface IVaultRepository {
    getSecret(path: string, key: string, defaultValue?: any): any;
    getAllSecrets(path: string): any;
    refreshSecrets(): Promise<void>;
    isAvailable(): boolean;
}