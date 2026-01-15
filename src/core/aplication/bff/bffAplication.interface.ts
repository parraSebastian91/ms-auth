import { AxiosResponse } from 'axios';
import {  Response } from 'express';

export interface IBffAplication {
    forwardRequest(
        service: string,
        method: string,
        path: string,
        body: any,
        userId: string,
        res: Response
    ): Promise<AxiosResponse<any, any>>;
}