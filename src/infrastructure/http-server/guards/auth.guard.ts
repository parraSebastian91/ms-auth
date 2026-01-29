import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Inject, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { IAuthService } from '../../../core/domain/puertos/inbound/IAuthService.interface';
import { AUTH_SERVICE } from '../../../core/core.module';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);
  constructor(
    @Inject(AUTH_SERVICE) private authService: IAuthService,
    private jwtService: JwtService,
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
    const session = this.extractSession(request);
    
    // this.logger.log(`Session completa:`, JSON.stringify(session || {}));
    
    if (!session) {
      throw new UnauthorizedException('No hay sesión activa. Por favor inicia sesión.');
    }
    
    if (!session.accessToken) {
      this.logger.error('Session existe pero accessToken es null/undefined');
      throw new UnauthorizedException('No hay token en la sesión.');
    }

    // this.logger.log(`Session accessToken (primeros 30 chars): ${session.accessToken?.substring(0, 30)}`);
    
    try {
      // Validar el token usando el servicio de autenticación
      const userId = await this.authService.validateToken(session.accessToken);
      this.logger.log(`authService.validateToken retornó userId:`, userId);

      if (!userId) {
        throw new UnauthorizedException('Token inválido o expirado');
      }

      // Verificar la estructura del token JWT para obtener información adicional
      const payload = this.jwtService.decode(session.accessToken) as any;
      this.logger.log(`JWT decoded payload:`, JSON.stringify(payload || {}));

      if (!payload) {
        throw new UnauthorizedException('Token malformado');
      }

      // Agregar información del usuario al request para uso posterior
      request['user'] = {
        userId: payload.id || payload.userId || payload.userUuid,
        username: payload.username || payload.sub,
        roles: payload.rol || payload.roles || [],
        permissions: payload.permisos || payload.permissions || [],
        accessToken: session.accessToken,
        typeDevice: session.typeDevice
      };

      return true;
    } catch (error) {
      this.logger.error(`AuthGuard error:`, error);
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      throw new UnauthorizedException('Error al validar el token');
    }
  }

  private extractSession(request: Request): any {
    return (request as any).session;
  }
}