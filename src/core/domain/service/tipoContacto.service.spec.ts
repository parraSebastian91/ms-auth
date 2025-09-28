import { TipoContactoService } from './tipoContacto.service';
import { TipoContactoNotFoundError } from '../../shared/errors/TipoContactoNotFound.error';
import { TipoContacto } from '../model/Entity/tipoContacto';

describe('TipoContactoService', () => {
  let service: TipoContactoService;
  let repoMock: any;

  beforeEach(() => {
    repoMock = {
      getAllTipoContacto: jest.fn(),
    };
    service = new TipoContactoService(repoMock);
  });

  it('debe retornar todos los tipos de contacto', async () => {
    const tipoContactoMock = { id: "1", nombre: 'Proveedor', descripcion: 'Un proveedor' };
    repoMock.getAllTipoContacto.mockResolvedValue([tipoContactoMock]);
    const result = await service.getAllTipoContacto();
    expect(Array.isArray(result)).toBe(true);
    expect(result[0]).toBeInstanceOf(TipoContacto);
    expect(result[0].nombre).toBe('Proveedor');
  });

  it('debe lanzar error si no hay tipos de contacto', async () => {
    repoMock.getAllTipoContacto.mockResolvedValue([]);
    await expect(service.getAllTipoContacto()).rejects.toThrow(TipoContactoNotFoundError);
  });

  it('debe lanzar error si el repositorio retorna null', async () => {
    repoMock.getAllTipoContacto.mockResolvedValue(null);
    await expect(service.getAllTipoContacto()).rejects.toThrow(TipoContactoNotFoundError);
  });
});