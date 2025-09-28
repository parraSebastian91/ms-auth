/*
https://docs.nestjs.com/fundamentals/testing#unit-testing
*/

import { Test } from '@nestjs/testing';
import { AuthAplicationService } from './authaplication.service';

describe('AuthaplicationService', () => {
    let authaplicationService: AuthAplicationService;

    beforeEach(async () => {
        const moduleRef = await Test.createTestingModule({
            imports: [], // Add
            controllers: [], // Add
            providers: [],   // Add
        }).compile();

        authaplicationService = moduleRef.get<AuthAplicationService>(AuthAplicationService);
    });

    it('should be defined', () => {
        expect(authaplicationService).toBeDefined();
    });
});
