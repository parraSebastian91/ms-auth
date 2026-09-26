/**
 * Respuestas idénticas para cuentas existentes e inexistentes (anti-enumeración). Están en un único sitio para
 * que caso de uso y controlador digan lo mismo y nadie las "afine" según el caso.
 */
export const GENERIC_MESSAGES = {
  passwordResetRequested: 'Si el correo existe, recibirás un enlace de restablecimiento',
  otpResent: 'Si el correo existe y no fue verificado, recibirás un nuevo código.',
} as const;
