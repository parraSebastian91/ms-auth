import { Injectable, CanActivate, ExecutionContext, UnauthorizedException, Inject, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { AUTH_SERVICE } from '../../../core/core.module';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { IAuthUseCase } from 'src/core/domain/puertos/inbound/IAuthUseCase.interface';
import { validateQuery } from 'src/core/aplication/useCase/auth/query/validate.query';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);
  constructor(
    @Inject(AUTH_SERVICE) private authService: IAuthUseCase,
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
    return await this.authService.ExecuteValidateSession(queryValidate);

  }

  private async extractSession(request: Request): Promise<string> {
    console.log('Extracting session from request cookies:', request.cookies['auth.session']);
    return request.cookies['auth.session'].split(':')[1].split('.')[0];;
  }
}