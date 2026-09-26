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
      sessionId: this.extractSession(request)
    }
    return await this.sessionUseCase.ExecuteValidateSession(queryValidate);

  }

  /**
   * Id de la sesión de express-session. Lo resuelve el middleware verificando la firma de la
   * cookie `auth.session`; no se parsea la cookie a mano (sin verificar y controlada por el cliente).
   */
  private extractSession(request: Request): string {
    const sessionId = (request as any).sessionID;
    if (!sessionId || typeof sessionId !== 'string') {
      this.logger.warn('Petición sin sesión de express-session');
      throw new UnauthorizedException('No session found');
    }
    return sessionId;
  }
}
