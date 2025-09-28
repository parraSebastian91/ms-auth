import { ValueObject } from "../../../share/ValueObject";


export class Celular extends ValueObject<string> {

    constructor(celular: string) { 
        super(celular, `Numero celular Inválido. EJ +56999999999 Número: ${celular}`) 
    }

    validate(celular: string): boolean {
        const res = /^\+?[1-9]\d{1,14}$/; // E.164 format
        return res.test(String(celular).toLowerCase());
    }
}