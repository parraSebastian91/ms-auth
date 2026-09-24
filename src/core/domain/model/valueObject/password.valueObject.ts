import { ValueObject } from "src/core/share/ValueObject";

export class Password extends ValueObject<string> {
    constructor(password: string) {
        super(password, `Invalid Password: ${password}`);
    }

    validate(password: string): boolean {
        if (password.length < 8) {
            return false;
        }
        if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
            return false;
        }
        return true;
    }
}