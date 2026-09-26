/** express-session usa callbacks; estas envolturas permiten esperar a que la operación termine. */
export type HttpSession = Record<string, any>;

export function saveSession(session: HttpSession): Promise<void> {
  return new Promise((resolve, reject) => session.save((err: any) => (err ? reject(err) : resolve())));
}

export function destroySession(session: HttpSession): Promise<void> {
  return new Promise((resolve, reject) => session.destroy((err: any) => (err ? reject(err) : resolve())));
}

/** Marca la sesión como autenticada y la persiste antes de responder. */
export async function establishAuthenticatedSession(session: HttpSession, accessToken: string): Promise<void> {
  session.authenticated = true;
  session.accessToken = accessToken;
  await saveSession(session);
}
