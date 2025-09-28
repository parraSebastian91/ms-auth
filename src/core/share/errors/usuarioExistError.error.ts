export class UserExistError extends Error {
    __proto__ = Error;
    constructor(message: string) {
        super(message);
        Object.setPrototypeOf(this, UserExistError.prototype);
    }
}   