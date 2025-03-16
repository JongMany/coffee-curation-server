import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpStatus,
} from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';

interface ICustomRpcException {
  code: number;
  details?: string; // { status: number; message: string; code: number };
  response: { statusCode: number; message: string; code: number };
}

@Catch()
export class AllGlobalExceptionsFilter implements ExceptionFilter {
  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: ICustomRpcException, host: ArgumentsHost): void {
    const { httpAdapter } = this.httpAdapterHost;
    const ctx = host.switchToHttp();

    const rpcError = exception.details
      ? JSON.parse(exception.details)
      : { ...exception.response, status: exception.response.statusCode };

    const httpStatus = rpcError.status
      ? rpcError.status
      : HttpStatus.INTERNAL_SERVER_ERROR;
    const rpcCode = exception.code;

    const responseBody = {
      statusCode: httpStatus,
      timestamp: new Date().toISOString(),
      path: httpAdapter.getRequestUrl(ctx.getRequest()),
      message: rpcError.message,
    };

    httpAdapter.reply(ctx.getResponse(), responseBody, httpStatus);
  }
}
