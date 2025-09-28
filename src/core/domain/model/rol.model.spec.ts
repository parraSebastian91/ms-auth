/*
https://docs.nestjs.com/fundamentals/testing#unit-testing
*/

import { Test } from '@nestjs/testing';
import { RolModel } from './rol.model';

describe('RolModel', () => {
    let rolModel: RolModel;

    beforeEach(async () => {
        const moduleRef = await Test.createTestingModule({
            imports: [], // Add
            controllers: [], // Add
            providers: [],   // Add
        }).compile();

        rolModel = moduleRef.get<RolModel>(RolModel);
    });

    it('should be defined', () => {
        expect(rolModel).toBeDefined();
    });
});
