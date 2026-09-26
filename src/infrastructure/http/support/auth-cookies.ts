import { CookieOptions, Request, Response } from 'express';

export const AUTH_COOKIES = {
  REFRESH: 'auth.refresh',
  SESSION: 'auth.session',
} as const;

const REFRESH_COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

function isHttps(req: Request): boolean {
  const forwarded = req.headers['x-forwarded-proto'];
  const proto = Array.isArray(forwarded) ? forwarded[0] : forwarded;
  return req.secure || proto === 'https';
}

export function refreshCookieOptions(req: Request, maxAge: number = REFRESH_COOKIE_MAX_AGE_MS): CookieOptions {
  return { httpOnly: true, secure: isHttps(req), sameSite: 'lax', maxAge, path: '/' };
}

export function setRefreshCookie(req: Request, res: Response, refreshToken: string): void {
  res.cookie(AUTH_COOKIES.REFRESH, refreshToken, refreshCookieOptions(req));
}

/** Borra las cookies de autenticación (refresh y sesión de express-session). */
export function clearAuthCookies(req: Request, res: Response): void {
  res.clearCookie(AUTH_COOKIES.REFRESH, refreshCookieOptions(req, 0));
  res.clearCookie(AUTH_COOKIES.SESSION, { httpOnly: true, secure: false, sameSite: 'lax', path: '/' });
}
