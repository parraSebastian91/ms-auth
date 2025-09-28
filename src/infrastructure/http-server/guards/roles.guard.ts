import { Injectable, CanActivate, ExecutionContext, ForbiddenException, Inject } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { IUsuarioAplication } from '../../../core/aplication/usuario/iUsuarioAplication.interface';
import { USUARIO_APPLICATION } from '../../../core/core.module';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    @Inject(USUARIO_APPLICATION) private usuarioApplication: IUsuarioAplication,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Verificar si la ruta está marcada como pública
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    
    if (isPublic) {
      return true;
    }

    // Obtener los roles requeridos para esta ruta
    const requiredRoles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    
    // Si no se especifican roles, permitir acceso (solo con autenticación)
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const user = request['user'];
    
    // Si no hay usuario en el request, significa que no pasó por AuthGuard
    if (!user || !user.userId) {
      throw new ForbiddenException('Usuario no autenticado');
    }

    try {
      // Obtener los roles del usuario desde la aplicación de usuarios
      const usuario = await this.usuarioApplication.findById(user.userId);
      
      if (!usuario || !usuario.rol) {
        throw new ForbiddenException('Usuario no encontrado o sin roles asignados');
      }

      // Extraer los nombres de los roles del usuario
      const userRoles = usuario.rol.map(rol => rol.nombre);
      
      // Verificar si el usuario tiene al menos uno de los roles requeridos
      const hasPermission = requiredRoles.some(role => userRoles.includes(role));
      
      if (!hasPermission) {
        throw new ForbiddenException(`Acceso denegado. Roles requeridos: ${requiredRoles.join(', ')}`);
      }

      // Agregar los roles del usuario al request para uso posterior
      request['user'].roles = userRoles;
      
      return true;
    } catch (error) {
      if (error instanceof ForbiddenException) {
        throw error;
      }
      throw new ForbiddenException('Error al verificar permisos del usuario');
    }
  }
}