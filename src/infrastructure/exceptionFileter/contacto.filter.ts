import { Catch, ExceptionFilter, ArgumentsHost, Logger, HttpStatus, ForbiddenException, UnauthorizedException } from "@nestjs/common";
import { Request, Response } from "express";
import { InsertError } from "../../core/share/errors/Insert.error";
import { ReqValidationError } from "../../core/share/errors/reqValidation.error";
import { EntityNotFoundError } from "../../core/share/errors/usuarioNotFound.error";
import { QueryFailedError, TypeORMError } from "typeorm";
import { UserExistError } from "src/core/share/errors/usuarioExistError.error";
import { UserNotFoundError } from "src/core/share/errors/UserNotFound.error";
import { ValidationError } from "src/core/share/errors/validation.error";

@Catch()
export class CoreExceptionFilter implements ExceptionFilter {
    catch(exception: any, host: ArgumentsHost) {
        const ctx = host.switchToHttp();
        const response = ctx.getResponse<Response>();
        const request = ctx.getRequest<Request>()

        let status = 500;
        let message = "Internal server error";

        if(exception instanceof UnauthorizedException) {
            Logger.warn(`UnauthorizedException: ${exception.message}`);
            status = HttpStatus.UNAUTHORIZED;
            message = exception.message;
        }else if(exception instanceof ValidationError) {
            Logger.warn(`ValidationError: ${exception.message}`);
            status = HttpStatus.BAD_REQUEST;
            message = exception.message;
        } else if(exception instanceof TypeORMError) {
            Logger.warn(`DB error: ${exception.message}`);
            status = HttpStatus.FORBIDDEN;
            message = exception.message;
        }
        else if (exception instanceof EntityNotFoundError) {
            Logger.warn(`EntityNotFoundError: ${exception.message}`);
            status = HttpStatus.NOT_FOUND;
            message = exception.message;
        }
        else if (exception instanceof InsertError) {
            Logger.warn(`InsertError: ${exception.message}`);
            status = HttpStatus.BAD_REQUEST;
            message = exception.message;
        }
        else if (exception instanceof ReqValidationError) {
            Logger.warn(`Validation error: ${exception.message}`);
            status = HttpStatus.BAD_REQUEST;
            message = exception.message;
        }
        else if (exception instanceof QueryFailedError) {
            Logger.error(`QueryFailedError: ${exception.message}`, exception.stack);
            status = HttpStatus.INTERNAL_SERVER_ERROR;
            message = "Database query failed";
        }
        else if (exception instanceof UserExistError) {
            Logger.warn(`UserExistError error: ${exception.message}`);
            status = HttpStatus.NOT_ACCEPTABLE;
            message = exception.message;
        }
        else if (exception instanceof UserNotFoundError) {
            Logger.warn(`UserNotFoundError error: ${exception.message}`);
            status = HttpStatus.NOT_FOUND;
            message = exception.message;
        }
        else if (exception instanceof ForbiddenException) {
            Logger.warn(`ForbiddenException error: ${exception.message}`);
            status = HttpStatus.FORBIDDEN;
            message = exception.message;
        }
        else {
            Logger.error(`Unexpected error: ${exception.message}`, exception.stack);
            status = HttpStatus.INTERNAL_SERVER_ERROR;
            message = "Internal server error";
        }

        response
            .status(status)
            .json({
                status: status,
                message: message
            });
    }
}