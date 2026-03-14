export class ReqValidationError extends Error {
    __proto__ = Error;
    constructor(message: string) {
        super(message);
        Object.setPrototypeOf(this, ReqValidationError.prototype);
    }
}   