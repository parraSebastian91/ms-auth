import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Inject, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { SESSION_USE_CASE, ISessionUseCase } from 'src/core/domain/puertos/inbound/ISessionUseCase.interface';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { validateQuery } from 'src/core/aplication/useCase/auth/query/validate.query';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);
  constructor(
    @Inject(SESSION_USE_CASE) private sessionUseCase: ISessionUseCase,
    private reflector: Reflector,
  ) { }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    const request = context.switchToHttp().getRequest<Request>();
    if (isPublic || request.path === '/metrics') {
      return true;
    }
    const queryValidate: validateQuery = {
      sessionId: await this.extractSession(request)
    }
    return await this.sessionUseCase.ExecuteValidateSession(queryValidate);

  }

  /** Extrae el sessionId de la cookie auth.session, lanzando 401 limpio
   *  si la cookie no vino en vez de romper con un TypeError. Mismo patrón
   *  ya usado en bff_seis_app/.../guards/auth.guard.ts. */
  private async extractSession(request: Request): Promise<string> {
    const rawSession = request.cookies?.['auth.session'];
    if (!rawSession || typeof rawSession !== 'string') {
      this.logger.warn('Cookie auth.session ausente o inválida');
      throw new UnauthorizedException('No session cookie found');
    }

    const sessionId = rawSession.split(':')[1]?.split('.')[0];
    if (!sessionId) {
      this.logger.warn('No fue posible extraer sessionId desde auth.session');
      throw new UnauthorizedException('Invalid session cookie format');
    }

    return sessionId;
  }
}