import { ArgumentsHost, Catch, RpcExceptionFilter } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { throwError } from 'rxjs';

export class CustomRpcException extends RpcException {
  message: string;
  name: string;
  cause?: unknown;
  stack?: string | undefined;
  status: number;
  code: number;
  // metadata: object;
  details: object;

  constructor(error: { code: number; status: number; message: string }) {
    super(error); // 🚀 `super()`를 사용하여 부모 클래스의 생성자를 호출
    this.message = JSON.stringify(error);
    this.code = error.code;
    this.status = error.status;
    this.name = 'CustomRpcException';
  }

  getError(): string | object {
    return super.getError(); // 🚀 부모 클래스의 `getError()`를 사용하여 오류 반환
  }
}

@Catch(RpcException)
export default class CustomRpcExceptionFilter
  implements RpcExceptionFilter<CustomRpcException>
{
  catch(exception: CustomRpcException, host: ArgumentsHost) {
    // const ctx = host.switchToHttp();
    // const response = ctx.getResponse<Response>();
    // const status =
    //   exception instanceof HttpException
    //     ? exception.getStatus()
    //     : HttpStatus.INTERNAL_SERVER_ERROR;
    // const message =
    //   exception instanceof HttpException
    //     ? exception.message
    //     : 'Internal Server Error';
    // return throwError(() => response.status(status).json({ message, status }));

    console.error('🛑 Custom RPC Exception Intercepted:', exception);
    return throwError(() => exception);

    // const errorResponse = exception.getError();
    // const grpcCode = errorResponse?.code || status.INVALID_ARGUMENT; // 기본값 3 (INVALID_ARGUMENT)
    // const grpcMessage = errorResponse?.message || 'Internal Server Error';

    // return throwError(
    //   () =>
    //     new RpcException({
    //       code: grpcCode,
    //       message: grpcMessage,
    //       status: errorResponse.status || 400, // HTTP 상태 코드
    //     }),
    // );
  }
}
