export class EntityBuildError extends Error {
    __proto__ = Error;
    constructor(message: string) {
        super(message);
        Object.setPrototypeOf(this, EntityBuildError.prototype);
    }
}