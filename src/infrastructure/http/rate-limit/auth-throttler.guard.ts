import { ExecutionContext, Injectable } from '@nestjs/common';
import { ThrottlerGuard, ThrottlerLimitDetail } from '@nestjs/throttler';

/**
 * ThrottlerGuard con la cabecera estándar `Retry-After`. Con limitadores nombrados (ip/account) la
 * librería solo emite `Retry-After-ip` / `Retry-After-account`, que los clientes no interpretan.
 */
@Injectable()
export class AuthThrottlerGuard extends ThrottlerGuard {
  protected async throwThrottlingException(context: ExecutionContext, detail: ThrottlerLimitDetail): Promise<void> {
    const seconds = detail.isBlocked ? detail.timeToBlockExpire : detail.timeToExpire;
    context.switchToHttp().getResponse().header('Retry-After', String(Math.max(1, Math.ceil(seconds))));
    await super.throwThrottlingException(context, detail);
  }
}
