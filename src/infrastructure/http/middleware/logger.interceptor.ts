/*
https://docs.nestjs.com/interceptors#interceptors
*/

import { Injectable, NestInterceptor, ExecutionContext, CallHandler, Logger } from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { Request, Response } from 'express';
import { randomUUID } from 'crypto';

@Injectable()
export class LoggerInterceptor implements NestInterceptor {
  private readonly logger = new Logger(LoggerInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();
    const requestIdHeader = request.headers['x-request-id'];
    const requestId = (Array.isArray(requestIdHeader) ? requestIdHeader[0] : requestIdHeader) || randomUUID();
    (request as any).requestId = requestId;
    response.setHeader('x-request-id', requestId);
    
    const { method, url, ip, sessionID } = request;
    const userAgent = (request as any).get?.('user-agent') || (request as any).headers?.['user-agent'];
    const startTime = Date.now();

    this.logger.log(`[ENTRADA] ${method} ${url} | RequestID: ${requestId} | IP: ${ip} | User-Agent: ${userAgent} | SessionID: ${sessionID}`);

    return next.handle().pipe(
      tap(() => {
        const duration = Date.now() - startTime;
        const statusCode = (response as any).statusCode;
        this.logger.log(`[SALIDA] ${method} ${url} | RequestID: ${requestId} | Status: ${statusCode} | Duración: ${duration}ms`);
      }),
      catchError((error) => {
        const duration = Date.now() - startTime;
        const statusCode = (response as any).statusCode || 500;
        const message = error?.message ?? error;
        this.logger.error(`[ERROR] ${method} ${url} | RequestID: ${requestId} | Status: ${statusCode} | Duración: ${duration}ms | Error: ${message}`);
        return throwError(() => error);
      })
    );
  }
}
