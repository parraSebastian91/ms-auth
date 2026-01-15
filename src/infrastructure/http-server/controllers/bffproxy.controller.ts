/*
https://docs.nestjs.com/controllers#controllers
*/

import { Controller, All, Req, Res, Param, UseInterceptors, Logger, Inject } from '@nestjs/common';
import { Request, Response } from 'express';

import { IBffAplication } from 'src/core/aplication/bff/bffAplication.interface';
import { BFF_APPLICATION } from 'src/core/core.module';

@Controller('bff')
export class BffProxyController {
    private readonly logger = new Logger(BffProxyController.name);
    constructor(
        @Inject(BFF_APPLICATION) private readonly bffAplicationService: IBffAplication,
    ) { }
    @All(':service/*')
    async proxy(
        @Param('service') service: string,
        @Req() req: Request,
        @Res() res: Response
    ) {
        try {
            const path = req.params[0] || ''; // ej: 'list', 'create', '123/edit'
            const userId = req['user']?.userId || null; // Asumiendo que el middleware de autenticación añade el usuario al request
            const method = req.method;
            const body = req.body;

            const result = await this.bffAplicationService.forwardRequest(
                service,
                method,
                path,
                body,
                userId,
                res
            );

            return res.status(200).json(result.data);
        } catch (error) {
            this.logger.error(`Proxy error:`, error);
            return res.status(error.getStatus?.() || 500).json({
                message: error.message,
                error: error.getResponse?.(),
            });
        }
    }
}

