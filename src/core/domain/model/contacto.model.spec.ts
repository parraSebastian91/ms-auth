import { ContactoModel } from './contacto.model';
import { Celular } from './valueObject/celular.valueObject';
import { Correo } from './valueObject/correo.ValueObject';
import { EntityBuildError } from '../../share/errors/EntityBuild.error';
import { TipoContactoModel } from './tipoContacto.model';

describe('Contacto Entity', () => {
  const contactoEntityMock = {
    id: "1",
    nombre: 'Juan Pérez',
    direccion: 'Calle Falsa 123',
    celular: '5551234567',
    correo: 'juan@email.com',
    rrss: 'https://twitter.com/juan',
    url: 'https://juan.com',
    imgBase64: 'dGVzdA==',
    tipoContacto: {
      id: 2,
      nombre: 'Cliente',
      descripcion: 'Un cliente'
    }
  };

  it('debe crear un Contacto correctamente', () => {
    const contacto = ContactoModel.create(contactoEntityMock as any);
    expect(contacto.nombre).toBe(contactoEntityMock.nombre);
    expect(contacto.direccion).toBe(contactoEntityMock.direccion);
    expect(contacto.celular).toBeInstanceOf(Celular);
    expect(contacto.correo).toBeInstanceOf(Correo);
    expect(contacto.tipoContacto).toBeInstanceOf(TipoContactoModel );
    expect(contacto.id.getValue()).toBe(contactoEntityMock.id.toString());
  });

  it('debe lanzar error si falta el id', () => {
    const mock = { ...contactoEntityMock, id: undefined };
    expect(() => Contacto.create(mock as any)).toThrow(EntityBuildError);
  });

  it('debe lanzar error si falta el nombre', () => {
    const mock = { ...contactoEntityMock, nombre: undefined };
    expect(() => Contacto.create(mock as any)).toThrow(EntityBuildError);
  });

  it('debe lanzar error si falta la direccion', () => {
    const mock = { ...contactoEntityMock, direccion: undefined };
    expect(() => Contacto.create(mock as any)).toThrow(EntityBuildError);
  });

  it('debe lanzar error si falta el celular', () => {
    const mock = { ...contactoEntityMock, celular: undefined };
    expect(() => Contacto.create(mock as any)).toThrow(EntityBuildError);
  });

  it('debe lanzar error si falta el correo', () => {
    const mock = { ...contactoEntityMock, correo: undefined };
    expect(() => Contacto.create(mock as any)).toThrow(EntityBuildError);
  });

  it('debe lanzar error si falta el tipoContacto', () => {
    const mock = { ...contactoEntityMock, tipoContacto: undefined };
    expect(() => Contacto.create(mock as any)).toThrow(EntityBuildError);
  });

  it('equalsTo debe comparar correctamente', () => {
    const contacto1 = Contacto.create(contactoEntityMock as any);
    const contacto2 = Contacto.create(contactoEntityMock as any);
    expect(contacto1.equalsTo(contacto2)).toBe(true);
  });
});