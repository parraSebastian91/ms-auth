export class InvalidcodeToken extends Error {
     __proto__ = Error;

    constructor(message: string) {
        super(message);
        Object.setPrototypeOf(this, InvalidcodeToken.prototype);
    }
}