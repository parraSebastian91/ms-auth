import { applyDecorators, Type } from '@nestjs/common';
import { ApiExtraModels, ApiProperty, ApiResponse, ApiResponseOptions, getSchemaPath } from '@nestjs/swagger';

/** Error estándar que produce CoreExceptionFilter. */
export class ErrorResponseDto {
  @ApiProperty({ example: 401 }) status: number;
  @ApiProperty({ example: 'Usuario o contraseña incorrectos' }) message: string;
}

/**
 * Documenta una respuesta con el sobre `{ status, message, data }` (ApiResponse). `data` puede ser
 * un DTO (`type`), un esquema libre (`schema`) o nulo.
 */
export function ApiEnvelopeResponse(opts: {
  status?: number;
  description: string;
  message: string;
  type?: Type<unknown>;
  isArray?: boolean;
  schema?: Record<string, any>;
  headers?: ApiResponseOptions['headers'];
}) {
  const status = opts.status ?? 200;
  let data: Record<string, any> = { nullable: true, example: null };
  if (opts.type) {
    const ref = { $ref: getSchemaPath(opts.type) };
    data = opts.isArray ? { type: 'array', items: ref } : ref;
  } else if (opts.schema) {
    data = opts.schema;
  }
  return applyDecorators(
    ...(opts.type ? [ApiExtraModels(opts.type)] : []),
    ApiResponse({
      status,
      description: opts.description,
      headers: opts.headers,
      schema: {
        type: 'object',
        properties: {
          status: { type: 'number', example: status },
          message: { type: 'string', example: opts.message },
          data,
        },
      },
    }),
  );
}

/** Errores frecuentes con el formato de ErrorResponseDto. */
export const ApiErrorResponse = (status: number, description: string) =>
  ApiResponse({ status, description, type: ErrorResponseDto });
