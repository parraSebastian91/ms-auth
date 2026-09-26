import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';

/** Exige al menos uno de los permisos de @Permissions(...). Va después de JwtAccessGuard. */
@Injectable()
export class PermissionsGuard implements CanActivate {
    constructor(private readonly reflector: Reflector) { }

    canActivate(context: ExecutionContext): boolean {
        const required = this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);
        if (!required || required.length === 0) return true;

        const user = context.switchToHttp().getRequest()['user'];
        if (!user?.userUuid) throw new ForbiddenException('Usuario no autenticado');

        const granted: string[] = user.permissions ?? [];
        if (!required.some(p => granted.includes(p))) {
            throw new ForbiddenException(`Acceso denegado. Permisos requeridos: ${required.join(', ')}`);
        }
        return true;
    }
}
