import { ValueObject } from "src/core/share/ValueObject";
import { EntityBuildError } from "src/core/domain/errors/EntityBuild.error";

export class NumeroDocumento extends ValueObject<string> {
    constructor(numeroDocumento: string) {
        super(numeroDocumento, `Invalid NumeroDocumento: ${numeroDocumento}`);
    }

    validate(numeroDocumento: string): boolean {
        // Validación genérica mínima cuando no se conoce el tipo documental.
        return typeof numeroDocumento === 'string' && numeroDocumento.trim().length >= 5;
    }

    static createForTipo(tipoDocumento: string, numeroDocumento: string): NumeroDocumento {
        if (!NumeroDocumento.validateByTipo(tipoDocumento, numeroDocumento)) {
            throw new EntityBuildError(`Invalid NumeroDocumento: ${numeroDocumento} for TipoDocumento: ${tipoDocumento}`);
        }

        return new NumeroDocumento(numeroDocumento);
    }

    static validateByTipo(tipoDocumento: string, numeroDocumento: string): boolean {
        const tipo = String(tipoDocumento ?? '').trim().toUpperCase();
        const numero = String(numeroDocumento ?? '').trim();

        if (!tipo || !numero) {
            return false;
        }

        switch (tipo) {
            case 'RUT':
                return NumeroDocumento.validateRut(numero);
            case 'DNI':
                return /^\d{7,12}$/.test(numero);
            case 'PASAPORTE':
                return /^[A-Z0-9]{6,15}$/i.test(numero);
            default:
                return false;
        }
    }

    private static validateRut(rawRut: string): boolean {
        const normalized = rawRut.replace(/[^0-9kK]/g, '').toUpperCase();
        if (!/^\d{7,8}[0-9K]$/.test(normalized)) {
            return false;
        }

        const body = normalized.slice(0, -1);
        const dv = normalized.slice(-1);
        return NumeroDocumento.calcDv(body) === dv;
    }

    private static calcDv(body: string): string {
        let sum = 0;
        let factor = 2;
        for (let i = body.length - 1; i >= 0; i--) {
            sum += parseInt(body[i], 10) * factor;
            factor = factor === 7 ? 2 : factor + 1;
        }
        const remainder = 11 - (sum % 11);
        if (remainder === 11) return '0';
        if (remainder === 10) return 'K';
        return String(remainder);
    }

}