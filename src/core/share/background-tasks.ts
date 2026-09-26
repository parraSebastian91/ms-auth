import { Logger } from '@nestjs/common';

/**
 * Ejecuta trabajo costoso FUERA de la ruta de respuesta. Es la pieza común de los flujos anti-enumeración
 * (reset de contraseña, reenvío de OTP): antes de responder solo se hace la consulta que es igual para cuentas
 * existentes e inexistentes; lo demás corre aquí, para que ni el cuerpo ni la duración de la respuesta revelen si
 * la cuenta existe. Los errores se registran y NUNCA llegan al cliente.
 *
 * Cada caso de uso que la usa debe exponer `whenIdle()` (pruebas) y esperar en `onModuleDestroy()` para no perder
 * correos pendientes al apagar el servicio.
 */
export class BackgroundTasks {
  private readonly pending = new Set<Promise<void>>();

  constructor(private readonly logger: Logger) {}

  run(label: string, task: () => Promise<void>): void {
    const promise: Promise<void> = Promise.resolve()
      .then(task)
      .catch((error: any) => this.logger.error(`[${label}] BACKGROUND_FAILED: ${error?.message ?? error}`))
      .finally(() => this.pending.delete(promise));
    this.pending.add(promise);
  }

  get size(): number {
    return this.pending.size;
  }

  /** Espera a que termine todo lo pendiente, incluido lo que se encole mientras tanto. */
  async whenIdle(): Promise<void> {
    while (this.pending.size > 0) await Promise.allSettled([...this.pending]);
  }
}
