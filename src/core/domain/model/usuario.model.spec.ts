/*
https://docs.nestjs.com/fundamentals/testing#unit-testing
*/

import { Test } from '@nestjs/testing';
import { UsuarioModel } from './usuario.model';

describe('UsuarioModel', () => {
    let usuarioModel: UsuarioModel;

    beforeEach(async () => {
        const moduleRef = await Test.createTestingModule({
            imports: [], // Add
            controllers: [], // Add
            providers: [],   // Add
        }).compile();

        usuarioModel = moduleRef.get<UsuarioModel>(UsuarioModel);
    });

    it('should be defined', () => {
        expect(usuarioModel).toBeDefined();
    });
});
