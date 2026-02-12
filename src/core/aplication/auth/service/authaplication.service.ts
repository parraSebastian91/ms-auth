/*
https://docs.nestjs.com/providers#services
*/

import { Injectable } from '@nestjs/common';
import { IAuthAplication } from '../authAplication.interface';
import { IAuthService } from 'src/core/domain/puertos/inbound/IAuthService.interface';
import { RefreshSession } from 'src/core/domain/model/RefreshSession.model';
import { authorizationCommand, LoginCommand, refreshSessionCommand, RequestPasswordResetCommand, ResetPasswordCommand, validateResetTokenCommand } from '../command/AuthCommand.interface';

@Injectable()
export class AuthAplicationService implements IAuthAplication {

    constructor(private authService: IAuthService) { }

   async refreshSession(command: refreshSessionCommand): Promise<{ accessToken: string, refreshToken: string } | null> {
        return this.authService.refreshSession(command.tokens,  command.typeDevice);
   }      

    async validateToken(token: string): Promise<string | null> {
        return this.authService.validateToken(token);
    }
    
    async authetication(command: LoginCommand): Promise<{ code: string, url: string }[] | null> {
        return this.authService.authetication(command.username, command.password, command.typeDevice, command.code_challenge, command.sessionId);
    }

    async exchangeCodeForToken(command: authorizationCommand): Promise<{ accessToken: string, refreshToken: string } | null> {
        return this.authService.exchangeCodeForToken(command.code, command.codeVerifier, command.typeDevice, command.sessionId);
    }

    async revokeUserSessions(session: RefreshSession): Promise<number> {
        return this.authService.revokeUserSessions(session);
    }

    async requestPasswordReset(command: RequestPasswordResetCommand): Promise<{ message: string }> {
        return this.authService.requestPasswordReset(command.correo, command.ip, command.userAgent);
    }

    async validateResetToken(command: validateResetTokenCommand): Promise<{ valid: boolean }> {
        return this.authService.validateResetToken(command.token, command.uuid);
    }

    async resetPassword(command: ResetPasswordCommand): Promise<{ message: string }> {
        return this.authService.resetPassword(command.token, command.uuid, command.newPassword, command.confirmPassword);
    }
}
