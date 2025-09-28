/*
https://docs.nestjs.com/fundamentals/testing#unit-testing
*/

import { Test } from '@nestjs/testing';
import { RolService } from './rol.service';

describe('RolService', () => {
    let rolService: RolService;

    beforeEach(async () => {
        const moduleRef = await Test.createTestingModule({
            imports: [], // Add
            controllers: [], // Add
            providers: [],   // Add
        }).compile();

        rolService = moduleRef.get<RolService>(RolService);
    });

    it('should be defined', () => {
        expect(rolService).toBeDefined();
    });
});
