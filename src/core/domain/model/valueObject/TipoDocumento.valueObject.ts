import { ValueObject } from "src/core/share/ValueObject";

export class TipoDocumento extends ValueObject<string> {
    constructor(tipoDocumento: string) {
        super(tipoDocumento, `Invalid TipoDocumento: ${tipoDocumento}`);
    }

    validate(tipoDocumento: string): boolean {
        const validTypes = ['DNI', 'RUT', 'PASAPORTE'];
        return validTypes.includes(tipoDocumento);
    }
}