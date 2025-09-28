import { DomainException } from "./errors/DomainException"
import { EntityBuildError } from "./errors/EntityBuild.error"


export abstract class ValueObject<T> {

    protected abstract validate(value: T): boolean;

    constructor(private primitiveValue: T, errorMessage: string) {
        if (!this.validate(primitiveValue)) throw new EntityBuildError(errorMessage)
    }

    getValue() {
        return this.primitiveValue
    }
}