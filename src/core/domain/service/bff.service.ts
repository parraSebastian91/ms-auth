/*
https://docs.nestjs.com/providers#services
*/

import { HttpException, Injectable, Logger } from '@nestjs/common';
import { IBffService } from '../puertos/inbound/IBffService.interface';
import { firstValueFrom } from 'rxjs';
import { HttpService } from '@nestjs/axios';
import { AxiosError, AxiosResponse } from 'axios';
import { Response } from 'express';


@Injectable()
export class BffService implements IBffService {


    private readonly logger = new Logger(BffService.name);

    private readonly microservices = {
        core: process.env.MS_CORE_URL || 'http://localhost:3001',
    };

    constructor(private httpService: HttpService) { }

    async forwardRequest(
        service: string,
        method: string,
        path: string,
        body: any,
        userId: string,
        res: Response
    ): Promise<AxiosResponse<any, any>> {
        // Validar que el microservicio exista
        if (!this.microservices[service]) {
            this.logger.warn(`Servicio desconocido: ${service}`);
            throw new HttpException(
                { message: `Microservicio '${service}' no encontrado` },
                404
            );
        }

        const baseUrl = this.microservices[service];
        const fullUrl = `${baseUrl}/${path}`;

        // Headers estándar
        const headers = {
            'Content-Type': 'application/json',
            'X-User-ID': userId,
            'X-Service': 'bff',
            'authorization': `Bearer ${res.req['user'].accessToken}` || '',
        };

        this.logger.log(`[${method}] ${service}/${path} (userId: ${userId})`);

        try {
            let observable$;
            switch (method.toUpperCase()) {
                case 'GET':
                    observable$ = this.httpService.get(fullUrl, { headers });
                    break;
                case 'POST':
                    observable$ = this.httpService.post(fullUrl, body, { headers });
                    break;
                case 'PUT':
                    observable$ = this.httpService.put(fullUrl, body, { headers });
                    break;
                case 'PATCH':
                    observable$ = this.httpService.patch(fullUrl, body, { headers });
                    break;
                case 'DELETE':
                    observable$ = this.httpService.delete(fullUrl, { headers });
                    break;
                default:
                    throw new HttpException({ message: `Método HTTP no soportado: ${method}` }, 400);
            }

            const response = await firstValueFrom(observable$ as any);
            return response as AxiosResponse<any>;
        } catch (error) {
            const err = error as AxiosError;
            this.logger.error(`Error proxy -> ${method} ${fullUrl}: ${err.message}`);
            if (err.response) {
                throw new HttpException(
                    { message: `Error en ${service}`, status: err.response.status, error: err.response.data },
                    err.response.status,
                );
            }
            throw new HttpException({ message: `Error al conectar con ${service}`, error: err.message }, 503);
        }
    }

    private getClientIp(req: any): string {
        return (
            req.ip ||
            req.headers['x-forwarded-for'] ||
            req.headers['x-real-ip'] ||
            req.socket.remoteAddress ||
            'unknown'
        );
    }
}