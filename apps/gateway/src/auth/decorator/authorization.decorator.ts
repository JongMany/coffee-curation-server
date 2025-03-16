import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';

export const Authorization = createParamDecorator(
  (_, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest<Request>();
    return request.headers['authorization'];
  },
);
