export class EmailNotVerifiedError extends Error {
    __proto__ = Error;
    readonly email: string;

    constructor(email: string) {
        super('Email no verificado');
        this.email = email;
        Object.setPrototypeOf(this, EmailNotVerifiedError.prototype);
    }
}
