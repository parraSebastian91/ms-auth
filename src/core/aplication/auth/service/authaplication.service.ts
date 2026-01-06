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

    async authetication(loginDto: { username: string, password: string, typeDevice: string, code_challenge: string }): Promise<string[] | null> {
        return this.authService.authetication(loginDto.username, loginDto.password, loginDto.typeDevice, loginDto.code_challenge);
    }

    async exchangeCodeForToken(code: string, typeDevice: string): Promise<{ access_token: string, refresh_token: string } | null> {
        return this.authService.exchangeCodeForToken(code, typeDevice);
    }
}
