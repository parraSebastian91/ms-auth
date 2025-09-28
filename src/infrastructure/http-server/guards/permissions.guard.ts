import { Injectable, CanActivate, ExecutionContext, ForbiddenException, Inject } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { PERMISSIONS_KEY } from '../decorators/permissions.decorator';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { IUsuarioAplication } from '../../../core/aplication/usuario/iUsuarioAplication.interface';
import { USUARIO_APPLICATION } from '../../../core/core.module';
import { JwtModule, JwtService } from '@nestjs/jwt';

@Injectable()
export class PermissionsGuard implements CanActivate {
    constructor(
        private reflector: Reflector,
        private jwtService: JwtService,
        @Inject(USUARIO_APPLICATION) private usuarioApplication: IUsuarioAplication,
    ) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        // Verificar si la ruta está marcada como pública
        const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        if (isPublic) {
            return true;
        }

        // Obtener los permisos requeridos para esta ruta
        const requiredPermissions = this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        // Obtener los roles requeridos como fallback
        const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        // Si no se especifican ni permisos ni roles, permitir acceso (solo con autenticación)
        if ((!requiredPermissions || requiredPermissions.length === 0) &&
            (!requiredRoles || requiredRoles.length === 0)) {
            return true;
        }

        const request = context.switchToHttp().getRequest<Request>();
        
        const user = request['user'];

        // Si no hay usuario en el request, significa que no pasó por AuthGuard
        if (!user || !user.userId) {
            throw new ForbiddenException('Usuario no autenticado');
        }

        // Extraer el token del header para decodificarlo
        const authHeader = request.headers.authorization;
        if (!authHeader) {
            throw new ForbiddenException('Token no encontrado');
        }

        const [, token] = authHeader.split(' ');
        if (!token) {
            throw new ForbiddenException('Token malformado');
        }

        try {
            // Decodificar el token JWT para obtener los datos completos
            const payload = this.jwtService.decode(token) as any;
            
            if (!payload) {
                throw new ForbiddenException('Token no válido');
            }

            // Verificar si el token tiene información de roles y permisos
            const tokenRoles = payload.rol || payload.roles || [];
            const tokenPermissions = payload.permisos || payload.permissions || [];

            console.log('Token payload:', payload);
            console.log('Roles del token (códigos):', tokenRoles);
            console.log('Permisos del token (códigos):', tokenPermissions);

            // Si el token tiene información, usarla directamente (códigos)
            let userRoles = tokenRoles;
            let userPermissions = tokenPermissions;

            // Si necesitas nombres en lugar de códigos, consultar la BD
            if (tokenRoles.length || tokenPermissions.length) {
                console.log('Usando roles y permisos del token');
                // Los datos del token son códigos, podrías usarlos directamente
                // o convertirlos a nombres si es necesario
            } else {
                // Si no hay información en el token, consultar la BD
                console.log('Token no tiene roles/permisos, consultando BD...');
                const usuario = await this.usuarioApplication.findById(user.userId);
                
                if (!usuario || !usuario.rol) {
                    throw new ForbiddenException('Usuario no encontrado o sin roles asignados');
                }

                // Extraer los nombres de los roles del usuario
                userRoles = usuario.rol.map(rol => rol.nombre);

                // Extraer todos los permisos de todos los roles del usuario
                userPermissions = usuario.rol
                    .flatMap(rol => rol.permisos || [])
                    .map(permiso => permiso.nombre);

                console.log('Roles desde BD (nombres):', userRoles);
                console.log('Permisos desde BD (nombres):', userPermissions);
            }

            // Validar permisos si se especificaron
            if (requiredPermissions && requiredPermissions.length > 0) {
                const hasRequiredPermission = requiredPermissions.some(permission =>
                    userPermissions.includes(permission)
                );

                if (!hasRequiredPermission) {
                    throw new ForbiddenException(
                        `Acceso denegado. Permisos requeridos: ${requiredPermissions.join(', ')}`
                    );
                }
            }
            // Si no hay permisos específicos, validar por roles (comportamiento anterior)
            else if (requiredRoles && requiredRoles.length > 0) {
                const hasRequiredRole = requiredRoles.some(role => userRoles.includes(role));

                if (!hasRequiredRole) {
                    throw new ForbiddenException(
                        `Acceso denegado. Roles requeridos: ${requiredRoles.join(', ')}`
                    );
                }
            }

            // Agregar información completa del usuario al request
            request['user'] = {
                ...user,
                roles: userRoles,
                permissions: userPermissions
            };

            return true;
        } catch (error) {
            if (error instanceof ForbiddenException) {
                throw error;
            }
            throw new ForbiddenException('Error al verificar permisos del usuario');
        }
    }
}