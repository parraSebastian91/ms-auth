/*
https://docs.nestjs.com/fundamentals/testing#unit-testing
*/

import { Test } from '@nestjs/testing';
import { SistemaModel } from './sistema.model';

describe('SistemaModel', () => {
    let sistemaModel: SistemaModel;

    beforeEach(async () => {
        const moduleRef = await Test.createTestingModule({
            imports: [], // Add
            controllers: [], // Add
            providers: [],   // Add
        }).compile();

        sistemaModel = moduleRef.get<SistemaModel>(SistemaModel);
    });

    it('should be defined', () => {
        expect(sistemaModel).toBeDefined();
    });
});
