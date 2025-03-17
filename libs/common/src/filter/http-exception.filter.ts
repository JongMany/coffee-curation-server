// import {
//   ArgumentsHost,
//   Catch,
//   ExceptionFilter,
//   HttpStatus,
// } from '@nestjs/common';
// import { RpcException } from '@nestjs/microservices';
// import { Response } from 'express';
// import { ErrorStatusMapper } from '../utils/error-status-mapper.util';

// import { Metadata, status } from '@grpc/grpc-js';

// interface CustomExceptionDetails {
//   type: string;
//   details: string;
//   domain: string;
//   metadata: { service: string };
// }
// interface CustomException<T> {
//   code: status;
//   details: T;
//   metadata: Metadata;
// }

// @Catch(RpcException)
// export class HttpExceptionFilter implements ExceptionFilter {
//   catch(exception: RpcException, host: ArgumentsHost) {
//     const err = exception.getError();
//     let _exception: CustomException<string>;
//     let details: CustomExceptionDetails;

//     if (typeof err === 'object') {
//       _exception = err as CustomException<string>;
//       details = <CustomExceptionDetails>JSON.parse(_exception.details);
//     }

//     // **You can log your exception details here**
//     // log exception (custom-logger)
//     const loggerService: LoggerService<CustomExceptionDetails> =
//       new LoggerService(FeatureService['CLIENT/UserAccountService']);

//     loggerService.log(<LogData<CustomExceptionDetails>>{
//       type: LogType.ERROR,
//       data: details,
//     });

//     const ctx = host.switchToHttp();
//     const response = ctx.getResponse<Response>();
//     // const request = ctx.getRequest<Request>();

//     const mapper = new ErrorStatusMapper();
//     const status = mapper.grpcToHttpMapper(_exception.code);
//     const type = HttpStatus[status];

//     response.status(status).json({
//       statusCode: status,
//       message: details.details,
//       error: type,
//     });
//   }
// }

// @Injectable()
// export class ErrorStatusMapper {
//   grpcToHttpMapper(status: status): HttpStatus {
//     let httpStatusEquivalent: HttpStatus;

//     switch (status) {
//       case status.OK:
//         httpStatusEquivalent = HttpStatus.OK;
//         break;

//       case status.CANCELLED:
//         httpStatusEquivalent = HttpStatus.METHOD_NOT_ALLOWED;
//         break;

//       case status.UNKNOWN:
//         httpStatusEquivalent = HttpStatus.BAD_GATEWAY;
//         break;

//       case status.INVALID_ARGUMENT:
//         httpStatusEquivalent = HttpStatus.UNPROCESSABLE_ENTITY;
//         break;

//       case status.DEADLINE_EXCEEDED:
//         httpStatusEquivalent = HttpStatus.REQUEST_TIMEOUT;
//         break;

//       case Status.NOT_FOUND:
//         httpStatusEquivalent = HttpStatus.NOT_FOUND;
//         break;

//       case Status.ALREADY_EXISTS:
//         httpStatusEquivalent = HttpStatus.CONFLICT;
//         break;

//       case Status.PERMISSION_DENIED:
//         httpStatusEquivalent = HttpStatus.FORBIDDEN;
//         break;

//       case Status.RESOURCE_EXHAUSTED:
//         httpStatusEquivalent = HttpStatus.TOO_MANY_REQUESTS;
//         break;

//       case Status.FAILED_PRECONDITION:
//         httpStatusEquivalent = HttpStatus.PRECONDITION_REQUIRED;
//         break;

//       case Status.ABORTED:
//         httpStatusEquivalent = HttpStatus.METHOD_NOT_ALLOWED;
//         break;

//       case Status.OUT_OF_RANGE:
//         httpStatusEquivalent = HttpStatus.PAYLOAD_TOO_LARGE;
//         break;

//       case Status.UNIMPLEMENTED:
//         httpStatusEquivalent = HttpStatus.NOT_IMPLEMENTED;
//         break;

//       case Status.INTERNAL:
//         httpStatusEquivalent = HttpStatus.INTERNAL_SERVER_ERROR;
//         break;

//       case Status.UNAVAILABLE:
//         httpStatusEquivalent = HttpStatus.NOT_FOUND;
//         break;

//       case Status.DATA_LOSS:
//         httpStatusEquivalent = HttpStatus.INTERNAL_SERVER_ERROR;
//         break;

//       case Status.UNAUTHENTICATED:
//         httpStatusEquivalent = HttpStatus.UNAUTHORIZED;
//         break;

//       default:
//         httpStatusEquivalent = HttpStatus.INTERNAL_SERVER_ERROR;
//         break;
//     }

//     return httpStatusEquivalent;
//   }
// }
