export const errorMessages: { [key: string]: string } = {
    USER_NOT_FOUND: "UserNotFound",
    INVALID_PASSWORD: "InvalidPassword",
    // ...otros errores
};

export class DomainException extends Error {
    constructor(message: string, name: string = 'DomainException') {
        super(message)
        this.message = message
        this.name = ''
    }
}