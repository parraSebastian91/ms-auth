/*
https://docs.nestjs.com/providers#services
*/

import { Injectable } from '@nestjs/common';
import { IAuthAplication } from '../authAplication.interface';
import { IAuthService } from 'src/core/domain/puertos/inbound/IAuthService.interface';

@Injectable()
export class AuthAplicationService implements IAuthAplication {

    constructor(private authService: IAuthService) { }

    async refreshToken(token: string, userId: string, typeDevice: string): Promise<{ access_token: string, refresh_token: string } | null> {
        return this.authService.refreshToken(token, userId, typeDevice);
    }

    async validateToken(token: string): Promise<string | null> {
        return this.authService.validateToken(token);
    }

    async login(loginDto: { username: string, password: string, typeDevice: string }): Promise<{ access_token: string, refresh_token: string } | null> {
        return this.authService.login(loginDto.username, loginDto.password, loginDto.typeDevice);
    }
}
