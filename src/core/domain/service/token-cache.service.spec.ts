/*
https://docs.nestjs.com/fundamentals/testing#unit-testing
*/

import { Test } from '@nestjs/testing';
import { TokenCacheService } from './token-cache.service';

describe('TokenCacheService', () => {
    let tokenCacheService: TokenCacheService;

    beforeEach(async () => {
        const moduleRef = await Test.createTestingModule({
            imports: [], // Add
            controllers: [], // Add
            providers: [],   // Add
        }).compile();

        tokenCacheService = moduleRef.get<TokenCacheService>(TokenCacheService);
    });

    it('should be defined', () => {
        expect(tokenCacheService).toBeDefined();
    });
});
