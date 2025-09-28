/*
https://docs.nestjs.com/providers#services
*/


import { Injectable } from '@nestjs/common';
import { TokenCacheService } from './token-cache.service';
import { UsuarioModel } from '../model/usuario.model';
import { IAuthService } from '../puertos/inbound/IAuthService.interface';
import { IUsuarioRepository } from '../puertos/outbound/iUsuarioRepository.interface';
import * as bcrypt from 'bcrypt';
import { UserNotFoundError } from 'src/core/share/errors/UserNotFound.error';
import { LoginError } from 'src/core/share/errors/LoginError.error';
import { JwtService } from '@nestjs/jwt';
import { randomBytes } from 'crypto';

@Injectable()
export class AuthService implements IAuthService {

    constructor(
        private usuarioRepository: IUsuarioRepository,
        private jwtService: JwtService,
        private tokenCacheService: TokenCacheService
    ) { }


    async refreshToken(token: string, userId: string, typeDevice: string): Promise<{ access_token: string, refresh_token: string } | null> {
        try {
            // Validar que el refresh_token esté en cache para ese usuario y dispositivo
            const storedToken = await this.tokenCacheService.getRefreshToken(userId, typeDevice);
            // valida si el token recivido es igual al que esta en cache
            if (!storedToken || storedToken !== token) return null;
            const usuarioDB = await this.usuarioRepository.getUsuarioById(Number(userId));
            if (!usuarioDB) return null;
            const usuario = UsuarioModel.create(usuarioDB);
            const payload = {
                id: usuario.id.getValue(),
                sub: usuario.userName,
                rol: usuario.rol.map(r => r.nombre),
                permisos: usuario.rol.flatMap(r => r.permisos ? r.permisos.map(p => p.nombre) : [])
            };
            const access_token = this.jwtService.sign(payload, { expiresIn: process.env.JWT_EXPIRES_IN, secret: process.env.JWT_SECRET });
            // Generar nuevo refresh_token
            const refresh_token = randomBytes(32).toString('hex');
            // Guardar el nuevo refresh_token y eliminar el anterior
            await this.tokenCacheService.deleteRefreshToken(userId, typeDevice);
            await this.tokenCacheService.setRefreshToken(refresh_token, userId, typeDevice, Number(process.env.JWT_REFRESH_EXPIRES_IN) );
            return { access_token, refresh_token };
        } catch (error) {
            return null;
        }
    }

    async validateToken(token: string): Promise<string | null> {
        try {
            this.jwtService.verify(token, { secret: process.env.JWT_SECRET });
            return token;
        } catch (error) {
            return null;
        }
    }

    async login(username: string, password: string, typeDevice: string): Promise<{ access_token: string, refresh_token: string } | null> {
        const usuarioDB = await this.usuarioRepository.getUsuarioByUsername(username)
        if (!usuarioDB) {
            throw new UserNotFoundError("Usuario no encontrado");
        }
        const usuario = usuarioDB ? UsuarioModel.create(usuarioDB) : null;
        if (!await bcrypt.compare(password, usuario.password)) {
            throw new LoginError("Usuario no encontrado o contraseña incorrecta");
        }
        delete usuario.password;
        const payload = {
            id: usuario.id.getValue(),
            sub: usuario.userName,
            rol: usuario.rol.map(r => r.codigo),
            permisos: usuario.rol.flatMap(r => r.permisos ? r.permisos.map(p => p.codigo) : [])
        };
        const access_token = this.jwtService.sign(payload, { expiresIn: process.env.JWT_EXPIRES_IN, secret: process.env.JWT_SECRET });
        // Generar refresh_token aleatorio
        const refresh_token = randomBytes(32).toString('hex');
        // Guardar el refresh_token en cache por usuario y dispositivo
        await this.tokenCacheService.setRefreshToken(refresh_token, String(usuario.id.getValue()), typeDevice, Number(process.env.JWT_REFRESH_EXPIRES_IN) ); // 7 días
        return { access_token, refresh_token };
    }
}
