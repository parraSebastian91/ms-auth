/*
https://docs.nestjs.com/fundamentals/testing#unit-testing
*/

import { Test } from '@nestjs/testing';
import { SistemaService } from './sistema.service';

describe('SistemaService', () => {
    let sistemaService: SistemaService;

    beforeEach(async () => {
        const moduleRef = await Test.createTestingModule({
            imports: [], // Add
            controllers: [], // Add
            providers: [],   // Add
        }).compile();

        sistemaService = moduleRef.get<SistemaService>(SistemaService);
    });

    it('should be defined', () => {
        expect(sistemaService).toBeDefined();
    });
});
