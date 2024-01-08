import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JwtPayload } from 'src/auth/types';

export const GetCurrentUserId = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): number => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user as JwtPayload;
    return user.sub;
  },
);
