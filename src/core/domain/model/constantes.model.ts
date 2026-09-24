export enum tipoDocumentoEnum {
    DNI = 'DNI',
    RUT = 'RUT',
    PASAPORTE = 'PASAPORTE'
}

export enum rolEnum {
    USUARIO_STANDARD = 'USUARIO_STANDARD',
    CEDENTE = 'CEDENTE',
    CEDENTE_ADM = 'CEDENTE_ADM',
    EJECUTIVO = 'EJECUTIVO',
    EJECUTIVO_ADM = 'EJECUTIVO_ADM'
}

export interface PHONE_PREFIX {
    code: string;
    label: string;
}

export interface PAIS {
    code: string;
    name: string;
}

export const PHONE_PREFIXES: PHONE_PREFIX[] = [
    { code: '+56', label: '🇨🇱 +56' },
    { code: '+54', label: '🇦🇷 +54' },
    { code: '+55', label: '🇧🇷 +55' },
    { code: '+52', label: '🇲🇽 +52' },
    { code: '+34', label: '🇪🇸 +34' },
    { code: '+1', label: '🇺🇸 +1' },
    { code: '+57', label: '🇨🇴 +57' },
    { code: '+51', label: '🇵🇪 +51' },
    { code: '+598', label: '🇺🇾 +598' },
    { code: '+593', label: '🇪🇨 +593' },
    { code: '+591', label: '🇧🇴 +591' },
    { code: '+595', label: '🇵🇾 +595' },
    { code: '+58', label: '🇻🇪 +58' },
];

export const PAISES: PAIS[] = [
    { code: 'CL', name: 'Chile' },
    { code: 'AR', name: 'Argentina' },
    { code: 'BR', name: 'Brasil' },
    { code: 'MX', name: 'México' },
    { code: 'ES', name: 'España' },
    { code: 'US', name: 'Estados Unidos' },
    { code: 'CO', name: 'Colombia' },
    { code: 'PE', name: 'Perú' },
    { code: 'UY', name: 'Uruguay' },
    { code: 'EC', name: 'Ecuador' },
    { code: 'BO', name: 'Bolivia' },
    { code: 'PY', name: 'Paraguay' },
    { code: 'VE', name: 'Venezuela' },
    { code: 'GT', name: 'Guatemala' },
    { code: 'HN', name: 'Honduras' },
    { code: 'CR', name: 'Costa Rica' },
    { code: 'PA', name: 'Panamá' },
    { code: 'DO', name: 'Rep. Dominicana' },
];