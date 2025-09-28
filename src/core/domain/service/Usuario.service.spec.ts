/*
https://docs.nestjs.com/fundamentals/testing#unit-testing
*/

import { Test } from '@nestjs/testing';
import { UsuarioService } from './Usuario.service';

describe('UsuarioService', () => {
    let usuarioService: UsuarioService;

    beforeEach(async () => {
        const moduleRef = await Test.createTestingModule({
            imports: [], // Add
            controllers: [], // Add
            providers: [],   // Add
        }).compile();

        usuarioService = moduleRef.get<UsuarioService>(UsuarioService);
    });

    it('should be defined', () => {
        expect(usuarioService).toBeDefined();
    });
});
