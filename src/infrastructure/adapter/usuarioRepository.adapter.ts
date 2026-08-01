import { InjectRepository } from '@nestjs/typeorm';
import { UsuarioEntity } from '../database/entities/usuario.entity';
import { Repository } from 'typeorm';
import { IUsuarioRepository } from '../../core/domain/puertos/outbound/iUsuarioRepository.interface';
import { Injectable, Logger } from '@nestjs/common';
import { UsuarioModel } from 'src/core/domain/model/usuario.model';
import { UsuarioMapper } from 'src/infrastructure/mapper/usuario.mapper';
import { RegistroUsuarioModel } from 'src/core/domain/model/registroUsuario.model';

@Injectable()
export class UsuarioRepositoryAdapter implements IUsuarioRepository {
  private readonly logger = new Logger(UsuarioRepositoryAdapter.name);
  constructor(
    @InjectRepository(UsuarioEntity)
    private readonly usuarioRepository: Repository<UsuarioEntity>,
  ) {}

  getValidId(): Promise<number> {
    return this.usuarioRepository.count().then((count) => count + 1);
  }

  getAllUsuarios(): Promise<UsuarioModel[]> {
    const usuariosEntity = this.usuarioRepository.find({
      relations: ['rol', 'contacto', 'contacto.tipoContacto'],
    });
    return usuariosEntity.then((usuarios) =>
      UsuarioMapper.toDomainList(usuarios),
    );
  }

  getUsuarioById(id: number): Promise<UsuarioModel> {
    return this.usuarioRepository
      .createQueryBuilder('usuario')
      .leftJoinAndSelect('usuario.rol', 'rol')
      .leftJoinAndSelect('usuario.contacto', 'contacto')
      .leftJoinAndSelect('contacto.tipoContacto', 'tipoContacto')
      .leftJoinAndSelect(
        'rol.permisos',
        'permisos',
        'permisos.activo = :activo',
        { activo: true },
      )
      .where('usuario.id = :id', { id })
      .getOne()
      .then((usuario) => (usuario ? UsuarioMapper.toDomain(usuario) : null));
  }

  async getUsuarioByUsername(username: string): Promise<UsuarioModel> {
    const usuario = await this.usuarioRepository
      .createQueryBuilder('usuario')
      .leftJoinAndSelect('usuario.rol', 'rol')
      .leftJoinAndSelect('usuario.contacto', 'contacto')
      .leftJoinAndSelect('contacto.tipoContacto', 'tipoContacto')
      .leftJoinAndSelect(
        'rol.permisos',
        'permisos',
        'permisos.activo = :activo',
        { activo: true },
      )
      .where('usuario.userName = :username', { username })
      .getOne();
    return usuario ? UsuarioMapper.toDomain(usuario) : null;
  }

  async getSystemsByUsername(username: string) {
    const usuario = await this.usuarioRepository
      .createQueryBuilder('usuario')
      .leftJoinAndSelect('usuario.rol', 'rol')
      .leftJoinAndSelect('rol.modulos', 'modulos')
      .leftJoinAndSelect('modulos.sistema', 'sistema')
      .where('usuario.userName = :username', { username })
      .andWhere('usuario.activo = :usuarioActivo', { usuarioActivo: true })
      .andWhere('sistema.activo = :sistemaActivo', { sistemaActivo: true })
      .getOne();

    // Deduplicar sistemas en memoria
    if (!usuario) return [];
    const sistemasUnicos = Array.from(
      new Map(
        usuario.rol
          .flatMap((r) => r.modulos.map((m) => m.sistema))
          .map((s) => [s.id, s]),
      ).values(),
    );
    return sistemasUnicos;
  }

  async createUsuario(
    data: RegistroUsuarioModel,
  ): Promise<{ usuarioUuid: string }> {
    const query = `
        INSERT INTO core.usuario (usuario_uuid, username, password_hash, activo, contacto_id, created_at, updated_at) 
        VALUES(gen_random_uuid(), $1, $2, false, $3, now(), now())
        returning usuario_uuid;
        `;
    try {
      const respuesta = await this.usuarioRepository.query(query, [
        data.username,
        data.passwordHash,
        data.contactoid,
      ]);
      return { usuarioUuid: respuesta[0].usuario_uuid };
    } catch (error) {
      this.logger.error('Error creating usuario:', error);
      throw new Error('Failed to create usuario');
    }
  }

  updateUsuario(id: number, data: UsuarioModel): Promise<UsuarioModel> {
    return this.usuarioRepository
      .save({ ...UsuarioMapper.toEntity(data), id })
      .then((savedUsuario) => UsuarioMapper.toDomain(savedUsuario))
      .catch(() => {
        throw new Error('Error updating usuario');
      });
  }

  async updatePassword(id: number, passwordHash: string): Promise<void> {
    await this.usuarioRepository
      .createQueryBuilder()
      .update()
      .set({ password: passwordHash })
      .where('id = :id', { id })
      .execute();
  }

  deleteUsuario(id: number): Promise<void> {
    return this.usuarioRepository.delete(id).then(() => {});
  }

  async marcarEmailVerificado(userUuid: string): Promise<void> {
    await this.usuarioRepository.query(
      `UPDATE core.usuario
             SET email_verificado = true, activo = true, email_verificado_at = now()
             WHERE usuario_uuid = $1`,
      [userUuid],
    );
  }

  async getUsuarioByEmail(
    email: string,
  ): Promise<{
    id: number;
    uuid: string;
    emailVerificado: boolean;
    nombres: string;
  } | null> {
    const result = await this.usuarioRepository.query(
      `SELECT u.usuario_id, u.usuario_uuid, u.email_verificado, c.nombres
             FROM core.usuario u
             JOIN core.contacto c ON c.contacto_id = u.contacto_id
             WHERE c.correo = $1
             LIMIT 1`,
      [email],
    );
    if (!result.length) return null;
    return {
      id: result[0].usuario_id,
      uuid: result[0].usuario_uuid,
      emailVerificado: result[0].email_verificado,
      nombres: result[0].nombres ?? '',
    };
  }

  async validateField(
    field: string,
    value: string,
  ): Promise<{ available: boolean; message?: string }> {
    let query = `select count(1) = 0 as available  from core.usuario u join core.contacto c on u.contacto_id  = c.contacto_id  `;
    let nombreCampo = '';
    switch (field) {
      case 'username':
        nombreCampo = 'Nombre de usuario';
        query += `where u.username = $1`;
        break;
      case 'email':
        nombreCampo = 'Correo electrónico';
        query += `where c.correo = $1`;
        break;
      default:
        return { available: false, message: 'Campo no válido para validación' };
    }
    try {
      const result = await this.usuarioRepository.query(query, [value]);
      console.log(
        `Validation result for field ${field} with value ${value}:`,
        result,
      );
      if (result[0].available) {
        return { available: true, message: `${nombreCampo} está disponible` };
      }
      return { available: false, message: `${nombreCampo} ya existe` };
    } catch (error) {
      this.logger.error(
        `Error validating field ${field} with value ${value}: ${error}`,
      );
      throw new Error('Error validating field');
    }
  }
}
