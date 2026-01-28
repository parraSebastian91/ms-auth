import { AxiosResponse } from 'axios';
import {  Response } from 'express';

export interface IBffAplication {
    forwardRequest(
        service: string,
        method: string,
        path: string,
        body: any,
        userId: string,
        token: string
    ): Promise<AxiosResponse<any, any>>;
}