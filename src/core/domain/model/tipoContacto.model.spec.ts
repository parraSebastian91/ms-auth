import { TipoContacto } from './tipoContacto.model';

describe('TipoContacto Entity', () => {
  const tipoContactoEntityMock = {
    id: "1",
    nombre: 'Proveedor',
    descripcion: 'Un proveedor'
  };

  it('debe crear un TipoContacto correctamente', () => {
    const tipoContacto = TipoContacto.create(tipoContactoEntityMock as any);
    expect(tipoContacto.nombre).toBe(tipoContactoEntityMock.nombre);
    expect(tipoContacto.descripcion).toBe(tipoContactoEntityMock.descripcion);
    expect(tipoContacto.id.getValue()).toBe(tipoContactoEntityMock.id.toString());
  });

  it('equalsTo debe comparar correctamente', () => {
    const tipo1 = TipoContacto.create(tipoContactoEntityMock as any);
    const tipo2 = TipoContacto.create(tipoContactoEntityMock as any);
    expect(tipo1.equalsTo(tipo2)).toBe(true);
  });

  it('equalsTo debe devolver false para ids diferentes', () => {
    const tipo1 = TipoContacto.create({ ...tipoContactoEntityMock, id: 1 } as any);
    const tipo2 = TipoContacto.create({ ...tipoContactoEntityMock, id: 2 } as any);
    expect(tipo1.equalsTo(tipo2)).toBe(false);
  });
});