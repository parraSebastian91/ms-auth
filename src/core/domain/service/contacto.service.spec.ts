import { ContactoService } from './contacto.service';
import { ContactoNotFoundError } from '../../shared/errors/contactoNotFound.error';
import { InsertError } from '../../shared/errors/Insert.error';
import { Contacto } from '../model/Entity/contacto';
import { ContactoDTO } from 'src/context/crud/infrastructure/http-server/model/dto/contacto.dto';

describe('ContactoService', () => {
  let service: ContactoService;
  let repoMock: any;

  beforeEach(() => {
    repoMock = {
      findById: jest.fn(),
      findAll: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    };
    service = new ContactoService(repoMock);
  });

  describe('findById', () => {
    it('debe retornar un contacto si existe', async () => {
      const contactoMock = { id: "1", nombre: 'Juan', direccion: 'Calle', celular: '123', correo: 'a@a.com', rrss: '', url: '', imgBase64: '', tipoContacto: { id: 1, nombre: '', descripcion: '' } };
      repoMock.findById.mockResolvedValue(contactoMock);
      const result = await service.findById('1');
      expect(result).toBeInstanceOf(Contacto);
    });

    it('debe lanzar error si no existe', async () => {
      repoMock.findById.mockResolvedValue(null);
      await expect(service.findById('1')).rejects.toThrow(ContactoNotFoundError);
    });
  });

  describe('findAll', () => {
    it('debe retornar una lista de contactos', async () => {
      const contactosMock = [
        { id: "1", nombre: 'Juan', direccion: 'Calle', celular: '123', correo: 'a@a.com', rrss: '', url: '', imgBase64: '', tipoContacto: { id: 1, nombre: '', descripcion: '' } }
      ];
      repoMock.findAll.mockResolvedValue(contactosMock);
      const result = await service.findAll();
      expect(Array.isArray(result)).toBe(true);
      expect(result[0]).toBeInstanceOf(Contacto);
    });

    it('debe lanzar error si no hay contactos', async () => {
      repoMock.findAll.mockResolvedValue([]);
      await expect(service.findAll()).rejects.toThrow(ContactoNotFoundError);
    });
  });

  describe('create', () => {
    it('debe crear un contacto correctamente', async () => {
      const dto: ContactoDTO = {
        id: '',
        nombre: 'Juan',
        direccion: 'Calle',
        celular: '123',
        correo: 'a@a.com',
        rrss: '',
        url: '',
        imgBase64: '',
        tipoContactoId: '1'
      };
      const createdMock = { ...dto, id: "1", tipoContacto: { id: "1", nombre: '', descripcion: '' } };
      repoMock.create.mockResolvedValue(createdMock);
      const result = await service.create(dto);
      expect(result).toBeInstanceOf(Contacto);
    });

    it('debe lanzar error si ocurre un error en la creación', async () => {
      repoMock.create.mockRejectedValue(new Error('fail'));
      await expect(service.create({} as any)).rejects.toThrow(InsertError);
    });
  });

  describe('update', () => {
    it('debe actualizar un contacto correctamente', async () => {
      const dto: ContactoDTO = {
        id: '',
        nombre: 'Juan',
        direccion: 'Calle',
        celular: '123',
        correo: 'a@a.com',
        rrss: '',
        url: '',
        imgBase64: '',
        tipoContactoId: '1'
      };
      const updatedMock = { ...dto, id: "1", tipoContacto: { id:"1", nombre: '', descripcion: '' } };
      repoMock.update.mockResolvedValue(updatedMock);
      const result = await service.update('1', dto);
      expect(result).toBeInstanceOf(Contacto);
    });

    it('debe lanzar error si ocurre un error en la actualización', async () => {
      repoMock.update.mockRejectedValue(new Error('fail'));
      await expect(service.update('1', {} as any)).rejects.toThrow(InsertError);
    });
  });

  describe('delete', () => {
    it('debe eliminar un contacto correctamente', async () => {
      repoMock.findById.mockResolvedValue({ id: 1 });
      repoMock.delete.mockResolvedValue(undefined);
      await expect(service.delete('1')).resolves.toBeUndefined();
    });

    it('debe lanzar error si el contacto no existe', async () => {
      repoMock.findById.mockResolvedValue(null);
      await expect(service.delete('1')).rejects.toThrow(ContactoNotFoundError);
    });

    it('debe lanzar error si ocurre un error en el borrado', async () => {
      repoMock.findById.mockResolvedValue({ id: 1 });
      repoMock.delete.mockRejectedValue(new Error('fail'));
      await expect(service.delete('1')).rejects.toThrow(InsertError);
    });
  });
});