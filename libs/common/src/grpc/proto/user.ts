// Code generated by protoc-gen-ts_proto. DO NOT EDIT.
// versions:
//   protoc-gen-ts_proto  v2.6.1
//   protoc               v5.29.3
// source: proto/user.proto

/* eslint-disable */
import { Metadata } from "@grpc/grpc-js";
import { GrpcMethod, GrpcStreamMethod } from "@nestjs/microservices";
import { Observable } from "rxjs";

export const protobufPackage = "user";

export interface ParseBearerTokenRequest {
  token: string;
}

export interface ParseBearerTokenResponse {
  sub: string;
}

export interface RegisterUserRequest {
  token: string;
  name: string;
  age: number;
  profile: string;
}

export interface RegisterUserResponse {
  id: string;
  email: string;
  name: string;
  age: number;
  profile: string;
}

export interface LoginUserRequest {
  token: string;
}

export interface LoginUserResponse {
  refreshToken: string;
  accessToken: string;
}

export interface DeleteUserRequest {
  token: string;
  email: string;
  password: string;
}

export interface DeleteUserResponse {
  message: string;
}

/** 클라이언트가 카카오 인증 코드(code)를 제공 */
export interface SignInWithKakaoRequest {
  code: string;
}

/** 카카오에서 반환된 사용자 정보 */
export interface SignInWithKakaoResponse {
  refreshToken: string;
  /**
   * string uid = 1;
   *   string email = 2;
   *   string nickname = 3;
   *   string profile_image = 4;
   */
  accessToken: string;
}

export interface GetUserInfoRequest {
  userId: string;
}

export interface GetUserInfoResponse {
  id: string;
  email: string;
  name: string;
  age: number;
  profile: string;
}

export const USER_PACKAGE_NAME = "user";

export interface AuthServiceClient {
  parseBearerToken(request: ParseBearerTokenRequest, metadata?: Metadata): Observable<ParseBearerTokenResponse>;

  registerUser(request: RegisterUserRequest, metadata?: Metadata): Observable<RegisterUserResponse>;

  loginUser(request: LoginUserRequest, metadata?: Metadata): Observable<LoginUserResponse>;

  deleteUser(request: DeleteUserRequest, metadata?: Metadata): Observable<DeleteUserResponse>;

  signInWithKakao(request: SignInWithKakaoRequest, metadata?: Metadata): Observable<SignInWithKakaoResponse>;
}

export interface AuthServiceController {
  parseBearerToken(
    request: ParseBearerTokenRequest,
    metadata?: Metadata,
  ): Promise<ParseBearerTokenResponse> | Observable<ParseBearerTokenResponse> | ParseBearerTokenResponse;

  registerUser(
    request: RegisterUserRequest,
    metadata?: Metadata,
  ): Promise<RegisterUserResponse> | Observable<RegisterUserResponse> | RegisterUserResponse;

  loginUser(
    request: LoginUserRequest,
    metadata?: Metadata,
  ): Promise<LoginUserResponse> | Observable<LoginUserResponse> | LoginUserResponse;

  deleteUser(
    request: DeleteUserRequest,
    metadata?: Metadata,
  ): Promise<DeleteUserResponse> | Observable<DeleteUserResponse> | DeleteUserResponse;

  signInWithKakao(
    request: SignInWithKakaoRequest,
    metadata?: Metadata,
  ): Promise<SignInWithKakaoResponse> | Observable<SignInWithKakaoResponse> | SignInWithKakaoResponse;
}

export function AuthServiceControllerMethods() {
  return function (constructor: Function) {
    const grpcMethods: string[] = ["parseBearerToken", "registerUser", "loginUser", "deleteUser", "signInWithKakao"];
    for (const method of grpcMethods) {
      const descriptor: any = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
      GrpcMethod("AuthService", method)(constructor.prototype[method], method, descriptor);
    }
    const grpcStreamMethods: string[] = [];
    for (const method of grpcStreamMethods) {
      const descriptor: any = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
      GrpcStreamMethod("AuthService", method)(constructor.prototype[method], method, descriptor);
    }
  };
}

export const AUTH_SERVICE_NAME = "AuthService";

export interface UserServiceClient {
  getUserInfo(request: GetUserInfoRequest, metadata?: Metadata): Observable<GetUserInfoResponse>;
}

export interface UserServiceController {
  getUserInfo(
    request: GetUserInfoRequest,
    metadata?: Metadata,
  ): Promise<GetUserInfoResponse> | Observable<GetUserInfoResponse> | GetUserInfoResponse;
}

export function UserServiceControllerMethods() {
  return function (constructor: Function) {
    const grpcMethods: string[] = ["getUserInfo"];
    for (const method of grpcMethods) {
      const descriptor: any = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
      GrpcMethod("UserService", method)(constructor.prototype[method], method, descriptor);
    }
    const grpcStreamMethods: string[] = [];
    for (const method of grpcStreamMethods) {
      const descriptor: any = Reflect.getOwnPropertyDescriptor(constructor.prototype, method);
      GrpcStreamMethod("UserService", method)(constructor.prototype[method], method, descriptor);
    }
  };
}

export const USER_SERVICE_NAME = "UserService";
