/**
 * Enmascarado de datos personales para logs. Los logs se recolectan (Loki) y duran más que la sesión:
 * no deben contener correos ni usernames completos. Para correlacionar un usuario usar su uuid.
 */
export function maskEmail(email?: string | null): string {
  if (!email) return '(vacío)';
  const at = email.lastIndexOf('@');
  if (at <= 0) return maskUsername(email);
  return `${email[0]}***${email.slice(at)}`;
}

export function maskUsername(value?: string | null): string {
  if (!value) return '(vacío)';
  return value.length <= 2 ? '***' : `${value.slice(0, 2)}***`;
}

/** Enmascara un identificador que puede ser correo o username (p. ej. el campo de login). */
export function maskIdentifier(value?: string | null): string {
  return value?.includes('@') ? maskEmail(value) : maskUsername(value);
}
