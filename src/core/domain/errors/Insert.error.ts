

export class InsertError extends Error {
    __proto__ = Error;

    constructor(message: string) {
        super(message);
        Object.setPrototypeOf(this, InsertError.prototype);
    }
}