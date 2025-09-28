/*
https://docs.nestjs.com/fundamentals/testing#unit-testing
*/

import { Test } from '@nestjs/testing';
import { AuthService } from './auth.service';

describe('AuthService', () => {
    let authService: AuthService;

    beforeEach(async () => {
        const moduleRef = await Test.createTestingModule({
            imports: [], // Add
            controllers: [], // Add
            providers: [],   // Add
        }).compile();

        authService = moduleRef.get<AuthService>(AuthService);
    });

    it('should be defined', () => {
        expect(authService).toBeDefined();
    });
});
