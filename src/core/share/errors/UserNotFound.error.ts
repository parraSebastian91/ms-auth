export class UserNotFoundError extends Error {
    __proto__ = Error;

    constructor(message: string) {
        super(message);
        Object.setPrototypeOf(this, UserNotFoundError.prototype);
    }
}