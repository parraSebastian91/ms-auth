import { ITipoContactoService } from 'src/core/domain/puertos/inbound/iTipoContacto.interface';
import { TipoContactoAplicationService } from './tipoContactoAplication.service';
import { TipoContactoEntity } from 'src/infrastructure/database/entities/tipoContacto.entity';
import { TipoContactoModel } from 'src/core/domain/model/tipoContacto.model';

describe('TipoContactoAplicationService', () => {
  let service: TipoContactoAplicationService;
  let tipoContactoServiceMock: jest.Mocked<ITipoContactoService>;

  beforeEach(() => {
    tipoContactoServiceMock = {
      getAllTipoContacto: jest.fn(),
    } as any;

    service = new TipoContactoAplicationService(tipoContactoServiceMock);
  });

  it('debe retornar todos los tipos de contacto', async () => {

    const tipoContactoEntity: TipoContactoEntity = {
      id: 1,
      nombre: 'Cliente',
      descripcion: 'Tipo cliente',
    } ;
    const tipos: TipoContactoModel[] = [
      TipoContactoModel.create(tipoContactoEntity),
      TipoContactoModel.create(tipoContactoEntity),
    ];
    tipoContactoServiceMock.getAllTipoContacto.mockResolvedValue(tipos);

    const result = await service.getAllTipoContacto();
    expect(tipoContactoServiceMock.getAllTipoContacto).toHaveBeenCalled();
    expect(result).toBe(tipos);
  });
});