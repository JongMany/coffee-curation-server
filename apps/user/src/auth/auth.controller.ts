import { UserMicroservice } from '@app/common';
import { status } from '@grpc/grpc-js';
import { Controller, InternalServerErrorException } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { AuthService } from './auth.service';

@Controller('auth')
@UserMicroservice.AuthServiceControllerMethods()
export class AuthController implements UserMicroservice.AuthServiceController {
  constructor(private readonly authService: AuthService) {}

  async registerUser(request: UserMicroservice.RegisterUserRequest) {
    const { token } = request;
    if (token === null) {
      throw new RpcException({
        code: status.UNAUTHENTICATED,
        message: '토큰을 입력해주세요',
      });
    }
    // try {
    const user = await this.authService.registerUser(request);
    if (!user) {
      throw new InternalServerErrorException('서버에서 오류가 발생했습니다.');
    }
    console.log('usr', user);
    return user;
  }

  async loginUser(request: UserMicroservice.LoginUserRequest) {
    return 'a' as any;
  }

  parseBearerToken(request: UserMicroservice.ParseBearerTokenRequest) {
    return this.authService.parseBearerToken({
      token: request.token,
      isRefreshToken: false,
    });
  }
}
