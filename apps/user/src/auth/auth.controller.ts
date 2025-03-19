import { CustomRpcException, UserMicroservice } from '@app/common';
import { Metadata, status } from '@grpc/grpc-js';
import { Controller, InternalServerErrorException } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
@UserMicroservice.AuthServiceControllerMethods()
export class AuthController implements UserMicroservice.AuthServiceController {
  constructor(private readonly authService: AuthService) {}

  async registerUser(request: UserMicroservice.RegisterUserRequest) {
    const { token } = request;
    if (token === null) {
      throw new CustomRpcException({
        status: 400,
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
    const { token } = request;
    if (token === null) {
      throw new CustomRpcException({
        status: 400,
        code: status.UNAUTHENTICATED,
        message: '토큰을 입력해주세요',
      });
    }

    return this.authService.login(token);
  }

  async parseBearerToken(request: UserMicroservice.ParseBearerTokenRequest) {
    return this.authService.parseBearerToken({
      token: request.token,
      isRefreshToken: false,
    });
  }

  async deleteUser(
    request: UserMicroservice.DeleteUserRequest,
    metadata?: Metadata,
  ) {
    const { token } = request;
    if (token === null) {
      throw new CustomRpcException({
        status: 400,
        code: status.UNAUTHENTICATED,
        message: '토큰을 입력해주세요',
      });
    }
    return this.authService.deleteUser(request);
  }

  async signInWithKakao(
    request: UserMicroservice.SignInWithKakaoRequest,
    metadata?: Metadata,
  ) {
    const { code } = request;
    const { accessToken, refreshToken } =
      await this.authService.signInWithKakao(code);
    return {
      accessToken,
      refreshToken,
    };
  }
}
