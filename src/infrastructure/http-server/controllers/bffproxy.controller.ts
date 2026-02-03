/*
https://docs.nestjs.com/controllers#controllers
*/

import { Controller, All, Req, Res, Param, Logger, Inject, Post, Body } from '@nestjs/common';
import { Request, Response } from 'express';

import { IBffAplication } from 'src/core/aplication/bff/bffAplication.interface';
import { BFF_APPLICATION } from 'src/core/core.module';
import { ServiciosDTO } from '../model/dto/servicios.dto';

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
                res.req['user'].accessToken
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

    @Post('/services')
    async requestServices(
        @Body() body: ServiciosDTO,
        @Res() res: Response,
        @Req() req: Request,
    ) {
        const servicios = body;
        const userId = req['user']?.userId || null;
        const msRespuestas = await Promise.all(
            Object.keys(servicios).map((service) => {
                this.logger.log(`Servicio solicitado: ${service}`);
                const { metodo, ruta, body = {} } = servicios[service];
                // normaliza: elimina el primer segmento (nombre del microservicio)
                const rutaClean = (this.replacePlaceholders(ruta, req['user']) || '').replace(/^\/+/, '');
                const parts = rutaClean.split('/').filter(Boolean);
                const servicio = parts.shift() || '';
                const rutaNormalizada = parts.join('/') || '';

                return this.bffAplicationService.forwardRequest(
                    servicio,
                    metodo,
                    rutaNormalizada,
                    body,
                    userId,
                    res.req['user'].accessToken
                );
            })
        );
        let response = {};

        // Normalizar a objetos serializables (por ejemplo { status, data })
        const payload = msRespuestas.map((r, i) => {
            if (r && typeof r === 'object' && 'data' in r) {
                return { data: r.data };
            }
            return r;
        });

        payload.forEach((r, i) => {
            //this.logger.log(`Respuesta del servicio ${Object.keys(servicios)[i]}: ${JSON.stringify(r)}`);
            response = { ...response, [Object.keys(servicios)[i]]: r.data || r };
        });

        return res.status(200).json(response);
    }

    replacePlaceholders(route: string, context: Record<string, any>): string {
        return route.replace(/:([a-zA-Z0-9_]+):?/g, (_, key) => {
            const v = context?.[key];
            return v === undefined || v === null ? '' : String(v);
        });
    }

}



