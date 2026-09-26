import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PermissionsGuard } from './permissions.guard';

function ctx(user: any) {
    const handler = () => undefined;
    return {
        getHandler: () => handler,
        getClass: () => class { },
        switchToHttp: () => ({ getRequest: () => ({ user }) }),
    } as unknown as ExecutionContext;
}

describe('PermissionsGuard', () => {
    const withRequired = (required?: string[]) => {
        const reflector = { getAllAndOverride: jest.fn().mockReturnValue(required) } as unknown as Reflector;
        return new PermissionsGuard(reflector);
    };

    it('permite si la ruta no exige permisos', () => {
        expect(withRequired(undefined).canActivate(ctx(undefined))).toBe(true);
    });

    it('rechaza si no hay usuario autenticado', () => {
        expect(() => withRequired(['USR_VIEW']).canActivate(ctx(undefined))).toThrow(ForbiddenException);
    });

    it('rechaza si el token no trae el permiso', () => {
        expect(() => withRequired(['USR_VIEW']).canActivate(ctx({ userUuid: 'u', permissions: ['ORG_VIEW'] }))).toThrow(ForbiddenException);
    });

    it('permite si trae al menos uno de los permisos', () => {
        expect(withRequired(['USR_VIEW', 'USR_EDIT']).canActivate(ctx({ userUuid: 'u', permissions: ['USR_EDIT'] }))).toBe(true);
    });
});
