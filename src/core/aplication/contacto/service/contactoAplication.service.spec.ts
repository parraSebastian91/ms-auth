import { IContactoService } from 'src/core/domain/puertos/inbound/iContactoService.interface';
import { ContactoAplicationService } from './contactoAplication.service';
import { ContactoModel } from 'src/core/domain/model/contacto.model';


describe('ContactoAplicationService', () => {
  let service: ContactoAplicationService;
  let contactoServiceMock: jest.Mocked<IContactoService>;

  beforeEach(() => {
    contactoServiceMock = {
      findById: jest.fn(),
      findAll: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
      delete: jest.fn(),
    } as any;

    service = new ContactoAplicationService(contactoServiceMock);
  });

  it('should call findById', async () => {
    const contacto = {} as ContactoModel;
    contactoServiceMock.findById.mockResolvedValue(contacto);

    const result = await service.findById('1');
    expect(contactoServiceMock.findById).toHaveBeenCalledWith('1');
    expect(result).toBe(contacto);
  });

  it('should call findAll', async () => {
    const contactos = [{} as ContactoModel];
    contactoServiceMock.findAll.mockResolvedValue(contactos);

    const result = await service.findAll();
    expect(contactoServiceMock.findAll).toHaveBeenCalled();
    expect(result).toBe(contactos);
  });

  it('should call create', async () => {
    const data = { nombre: 'Test' };
    const contacto = {} as ContactoModel;
    contactoServiceMock.create.mockResolvedValue(contacto);

    const result = await service.create(data);
    expect(contactoServiceMock.create).toHaveBeenCalledWith(data);
    expect(result).toBe(contacto);
  });

  it('should call update', async () => {
    const data = { nombre: 'Test' };
    const contacto = {} as ContactoModel;
    contactoServiceMock.update.mockResolvedValue(contacto);

    const result = await service.update('1', data);
    expect(contactoServiceMock.update).toHaveBeenCalledWith('1', data);
    expect(result).toBe(contacto);
  });

  it('should call delete', async () => {
    contactoServiceMock.delete.mockResolvedValue();

    await service.delete('1');
    expect(contactoServiceMock.delete).toHaveBeenCalledWith('1');
  });
});