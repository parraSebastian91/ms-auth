import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { AccessTokenPayload } from '../../../core/domain/model/jwt.model';

/** Valida el JWT de acceso (Bearer) para endpoints que consume el BFF/ms-core. */
@Injectable()
export class JwtAccessGuard implements CanActivate {
    constructor(private readonly jwtService: JwtService) { }

    canActivate(context: ExecutionContext): boolean {
        const request = context.switchToHttp().getRequest<Request>();
        const [type, token] = request.headers.authorization?.split(' ') ?? [];
        if (type !== 'Bearer' || !token) {
            throw new UnauthorizedException('Token de acceso requerido');
        }
        let payload: AccessTokenPayload;
        try {
            payload = this.jwtService.verify<AccessTokenPayload>(token);
        } catch {
            throw new UnauthorizedException('Token inválido o expirado');
        }
        request['user'] = {
            userId: payload.userId,
            username: payload.username,
            userUuid: payload.userUuid,
            roles: payload.roles ?? [],
            permissions: payload.permissions ?? [],
        };
        return true;
    }
}
