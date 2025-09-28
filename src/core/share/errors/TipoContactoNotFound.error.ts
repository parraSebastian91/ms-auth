export class TipoContactoNotFoundError extends Error {

    __proto__ = Error;
    constructor(message: string) {
        super(message);
        Object.setPrototypeOf(this, TipoContactoNotFoundError.prototype);
    }
}