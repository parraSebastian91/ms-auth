
export interface IContactoAplication {
    findById(id: string): Promise<any | null>;
    findAll(): Promise<any[] | null>;
    create(data: any): Promise<any>;
    update(id: string, data: any): Promise<any>;
    delete(id: string): Promise<void>;
}