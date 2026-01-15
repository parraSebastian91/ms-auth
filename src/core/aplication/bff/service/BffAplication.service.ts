/*
https://docs.nestjs.com/providers#services
*/

import { Injectable } from '@nestjs/common';
import { IBffAplication } from '../bffAplication.interface';
import { IBffService } from 'src/core/domain/puertos/inbound/IBffService.interface';
import { Response } from 'express';
@Injectable()
export class BffAplicationService implements IBffAplication {

    constructor(
        private readonly bffService: IBffService
    ) { }

    async forwardRequest(
        service: string,
        method: string,
        path: string,
        body: any,
        userId: string,
        res: Response) : Promise<any> {
            return this.bffService.forwardRequest(
                service,
                method,
                path,
                body,
                userId,
                res
            );
    }

}
