import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export interface CurrentUserData {
  userId: string;
  username: string;
  roles: string[];
  permissions: string[];
  token?: string; // Token original (opcional)
}

export const CurrentUser = createParamDecorator(
  (data: keyof CurrentUserData | undefined, ctx: ExecutionContext): CurrentUserData | any => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;

    return data ? user?.[data] : user;
  },
);