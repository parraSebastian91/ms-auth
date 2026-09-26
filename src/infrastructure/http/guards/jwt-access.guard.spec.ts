import { ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtAccessGuard } from './jwt-access.guard';

const ctx = (headers: any, request: any = { headers }) =>
    ({ switchToHttp: () => ({ getRequest: () => request }) }) as unknown as ExecutionContext;

describe('JwtAccessGuard', () => {
    const jwt = new JwtService({ secret: 'test-secret' });
    const guard = new JwtAccessGuard(jwt);

    it('rechaza sin Authorization', () => {
        expect(() => guard.canActivate(ctx({}))).toThrow(UnauthorizedException);
    });

    it('rechaza esquemas distintos de Bearer', () => {
        expect(() => guard.canActivate(ctx({ authorization: 'Basic abc' }))).toThrow(UnauthorizedException);
    });

    it('rechaza un token firmado con otro secreto', () => {
        const bad = new JwtService({ secret: 'otro' }).sign({ userUuid: 'u' });
        expect(() => guard.canActivate(ctx({ authorization: `Bearer ${bad}` }))).toThrow(UnauthorizedException);
    });

    it('rechaza un token expirado', () => {
        const expired = jwt.sign({ userUuid: 'u' }, { expiresIn: -10 });
        expect(() => guard.canActivate(ctx({ authorization: `Bearer ${expired}` }))).toThrow(UnauthorizedException);
    });

    it('acepta un token válido y expone user en el request', () => {
        const token = jwt.sign({ userId: 7, username: 'ana', userUuid: 'uuid-1', roles: ['ADMIN'], permissions: ['USR_VIEW'] });
        const request: any = { headers: { authorization: `Bearer ${token}` } };
        expect(guard.canActivate(ctx(null, request))).toBe(true);
        expect(request.user).toMatchObject({ userUuid: 'uuid-1', roles: ['ADMIN'], permissions: ['USR_VIEW'] });
    });
});
