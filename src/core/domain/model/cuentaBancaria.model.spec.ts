/*
https://docs.nestjs.com/fundamentals/testing#unit-testing
*/

import { Test } from '@nestjs/testing';
import { CuentaBancariaModel } from './cuentaBancaria.model';

describe('CuentaBancariaModel', () => {
    let cuentaBancariaModel: CuentaBancariaModel;

    beforeEach(async () => {
        const moduleRef = await Test.createTestingModule({
            imports: [], // Add
            controllers: [], // Add
            providers: [],   // Add
        }).compile();

        cuentaBancariaModel = moduleRef.get<CuentaBancariaModel>(CuentaBancariaModel);
    });

    it('should be defined', () => {
        expect(cuentaBancariaModel).toBeDefined();
    });
});
