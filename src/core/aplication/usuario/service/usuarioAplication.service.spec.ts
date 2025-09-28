/*
https://docs.nestjs.com/fundamentals/testing#unit-testing
*/

import { Test } from '@nestjs/testing';
import { UsuarioAplicationService } from './usuarioAplication.service';

describe('UsuarioAplicationService', () => {
    let usuarioAplicationService: UsuarioAplicationService;

    beforeEach(async () => {
        const moduleRef = await Test.createTestingModule({
            imports: [], // Add
            controllers: [], // Add
            providers: [],   // Add
        }).compile();

        usuarioAplicationService = moduleRef.get<UsuarioAplicationService>(UsuarioAplicationService);
    });

    it('should be defined', () => {
        expect(usuarioAplicationService).toBeDefined();
    });
});
