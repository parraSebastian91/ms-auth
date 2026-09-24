
export class SessionExistsError extends Error {
    __proto__ = Error;

    constructor(message: string) {
        super(message);
        Object.setPrototypeOf(this, SessionExistsError.prototype);
    }
}