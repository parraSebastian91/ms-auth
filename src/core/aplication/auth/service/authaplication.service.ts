/*
https://docs.nestjs.com/providers#services
*/

import { Injectable } from '@nestjs/common';
import { IAuthAplication } from '../authAplication.interface';
import { IAuthService } from 'src/core/domain/puertos/inbound/IAuthService.interface';
import { RefreshSession } from 'src/core/domain/model/RefreshSession.model';

@Injectable()
export class AuthAplicationService implements IAuthAplication {

    constructor(private authService: IAuthService) { }

   async refreshSession(refreshToken: Record<string, any>, typeDevice: string): Promise<{ accessToken: string, refreshToken: string } | null> {
        return this.authService.refreshSession(refreshToken,  typeDevice);
   }      

    async validateToken(token: string): Promise<string | null> {
        return this.authService.validateToken(token);
    }
    
    async authetication(loginDto: { username: string, password: string, typeDevice: string, code_challenge: string, sessionId: string }): Promise<{ code: string, url: string }[] | null> {
        return this.authService.authetication(loginDto.username, loginDto.password, loginDto.typeDevice, loginDto.code_challenge, loginDto.sessionId);
    }

    async exchangeCodeForToken(code: string, codeVerifier: string, typeDevice: string, sessionId: string): Promise<{ accessToken: string, refreshToken: string } | null> {
        return this.authService.exchangeCodeForToken(code, codeVerifier, typeDevice, sessionId);
    }

    async revokeUserSessions(session: RefreshSession): Promise<number> {
        return this.authService.revokeUserSessions(session);
    }

    async requestPasswordReset(
        email: string,
        ipAddress?: string,
        userAgent?: string
    ): Promise<{ message: string }> {
        return this.authService.requestPasswordReset(email, ipAddress, userAgent);
    }

    async validateResetToken(
        token: string,
        uuid?: string
    ): Promise<{ valid: boolean }> {
        return this.authService.validateResetToken(token, uuid);
    }

    async resetPassword(
        token: string,
        uuid: string,
        newPassword: string,
        confirmPassword: string
    ): Promise<{ message: string }> {
        return this.authService.resetPassword(token, uuid, newPassword, confirmPassword);
    }


}
