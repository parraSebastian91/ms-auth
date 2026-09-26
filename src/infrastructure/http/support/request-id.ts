import { Request } from 'express';

/** Id de correlación de la petición: cabecera x-request-id o el que asignó el middleware. */
export function getRequestId(req: Request): string {
  const header = req.headers['x-request-id'];
  const requestId = Array.isArray(header) ? header[0] : header;
  return requestId || (req as any).requestId || 'N/A';
}
