import { Id } from "./valueObject/id.valueObject";

export abstract class Entity<T>{

    id: Id;
 
    abstract equalsTo(entity: T): boolean;
}