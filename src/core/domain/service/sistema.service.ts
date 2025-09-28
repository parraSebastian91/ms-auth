/*
https://docs.nestjs.com/providers#services
*/

import { Injectable } from '@nestjs/common';
import { ISistemaService } from '../puertos/inbound/ISistemaService.interface';
import { ISistemaRepository } from '../puertos/outbound/ISistemaRepository.interface';
import { SistemaDTO } from '../DTO/sistema.dto';

@Injectable()
export class SistemaService implements ISistemaService {

    constructor(private sistemaRepository: ISistemaRepository) { }


    async getSistemaByUsername(username: string): Promise<SistemaDTO | null> {

        const sistemas = await this.sistemaRepository.getSistemaByUsername(username);

        if (!sistemas) {
            return null;
        }

        const sistemaArray: SistemaDTO = {
            username: sistemas[0].username,
            nombre: sistemas[0].nombre,
            razon_social: sistemas[0].razon_social,
            sistemas: []
        };

        sistemas.forEach(s => {
            let sistema = sistemaArray.sistemas.find(sis => sis.id === s.sistemaid);
            if (!sistema) {
                sistema = {
                    id: s.sistemaid,
                    nombre: s.sistemanombre,
                    path: s.sistemapath,
                    modulos: []
                };
                sistemaArray.sistemas.push(sistema);
            }

            let modulo = sistema.modulos.find(mod => mod.id === s.moduloid);
            if (!modulo) {
                modulo = {
                    id: s.moduloid,
                    nombre: s.modulonombre,
                    path: s.modulopath,
                    funcionalidades: []
                };
                sistema.modulos.push(modulo);
            }

            let funcionalidad = modulo.funcionalidades.find(func => func.id === s.funcionalidadid);
            if (!funcionalidad) {
                funcionalidad = {
                    id: s.funcionalidadid,
                    nombre: s.funcionalidadnombre,
                    path: s.funcionalidadpath
                };
                modulo.funcionalidades.push(funcionalidad);
            }
        });

        return sistemaArray;
    }
}
