interface SistemaDTO {
    username: string;
    nombre: string;
    razon_social: string;
    sistemas: {
        id: number;
        nombre: string;
        path: string;
        modulos: {
            id: number;
            nombre: string;
            path: string;
            funcionalidades: {
                id: number;
                nombre: string;
                path: string;
            }[];
        }[];
    }[];
}

interface FromEntitySistemaDTO {
    username: string;
    nombre:string;
    razon_social: string;
    sistemaid: number;
    sistemanombre: string;
    sistemapath: string;
    moduloid: number;
    modulonombre: string;
    modulopath: string;
    funcionalidadid: number;
    funcionalidadnombre: string;
    funcionalidadpath: string;
}

export { SistemaDTO, FromEntitySistemaDTO };