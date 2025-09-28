/*
https://docs.nestjs.com/fundamentals/testing#unit-testing
*/

import { Test } from '@nestjs/testing';
import { ModuloModel } from './modulo.model';

describe('ModuloModel', () => {
    let moduloModel: ModuloModel;

    beforeEach(async () => {
        const moduleRef = await Test.createTestingModule({
            imports: [], // Add
            controllers: [], // Add
            providers: [],   // Add
        }).compile();

        moduloModel = moduleRef.get<ModuloModel>(ModuloModel);
    });

    it('should be defined', () => {
        expect(moduloModel).toBeDefined();
    });
});
