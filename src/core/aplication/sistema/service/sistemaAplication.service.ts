/*
https://docs.nestjs.com/providers#services
*/

import { Injectable } from '@nestjs/common';
import { ISistemaAplicationService } from '../ISistemaAplication.interface';
import { ISistemaService } from 'src/core/domain/puertos/inbound/ISistemaService.interface';
import { SistemaDTO } from 'src/core/domain/DTO/sistema.dto';

@Injectable()
export class SistemaAplicationService implements ISistemaAplicationService {

    constructor(private sistemaService: ISistemaService) { }

    async getSistemaByUsername(username: string): Promise<SistemaDTO | null> {
        return this.sistemaService.getSistemaByUsername(username);
    }
}
