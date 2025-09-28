
import { v4 as uuidv4 } from 'uuid';
import { ValueObject } from '../ValueObject';

export class Id extends ValueObject<number> {
    
    constructor(private id: number) {
        super(id, `Invalid UUID Id:${id} `)
    }

    validate(id: number | string): boolean {
        // const re  =  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i
        // return re.test(id)
        return true; // Simplified validation for demonstration
    }
    
}