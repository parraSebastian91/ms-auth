/*
https://docs.nestjs.com/fundamentals/testing#unit-testing
*/

import { Test } from '@nestjs/testing';
import { PermisosModel } from './permisos.model';

describe('PermisosModel', () => {
    let permisosModel: PermisosModel;

    beforeEach(async () => {
        const moduleRef = await Test.createTestingModule({
            imports: [], // Add
            controllers: [], // Add
            providers: [],   // Add
        }).compile();

        permisosModel = moduleRef.get<PermisosModel>(PermisosModel);
    });

    it('should be defined', () => {
        expect(permisosModel).toBeDefined();
    });
});
