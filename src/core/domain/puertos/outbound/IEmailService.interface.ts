/**
 * Puerto de notificaciones por correo electrónico.
 * El use case depende de esta interfaz, nunca del adaptador concreto.
 * Para cambiar de proveedor (SMTP, SendGrid, SES, etc.) solo se
 * intercambia el adaptador en el módulo — sin tocar ningún use case.
 */
export interface IEmailService {
    /**
     * Envía el código de verificación de 6 dígitos al correo del usuario.
     * @param email   Correo destino
     * @param code    Código numérico de 6 dígitos (en texto plano)
     * @param nombre  Nombre del usuario para personalizar el mensaje
     */
    sendVerificationCode(email: string, code: string, nombre: string): Promise<void>;
}

export const EMAIL_SERVICE = 'EMAIL_SERVICE';
