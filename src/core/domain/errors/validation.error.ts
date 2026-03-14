export class ValidationError extends Error {
    __proto__ = Error;

    constructor(message: string) {
        super(message);
        Object.setPrototypeOf(this, ValidationError.prototype);
    }
}
