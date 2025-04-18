import { USER_SERVICE, UserMicroservice } from '@app/common';
import { AUTH_MICROSERVICE } from '@app/common/constants/microservices';
import { Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { ClientGrpc } from '@nestjs/microservices';
import { catchError, lastValueFrom } from 'rxjs';
import { DeleteUserDto } from './dto/delete-user.dto';
import { RegisterUserDto } from './dto/register-user.dto';
import { SignInKakaoUserInfoDto } from './dto/signin-kakao-user-info.dto';

@Injectable()
export class AuthService implements OnModuleInit {
  private authService: UserMicroservice.AuthServiceClient;

  constructor(
    @Inject(USER_SERVICE)
    private readonly userMicroservice: ClientGrpc,
  ) {}
  onModuleInit() {
    this.authService =
      this.userMicroservice.getService<UserMicroservice.AuthServiceClient>(
        AUTH_MICROSERVICE,
      );
  }

  async registerUser(registerUserDto: { token: string } & RegisterUserDto) {
    return await lastValueFrom(
      this.authService.registerUser({ ...registerUserDto }).pipe(
        catchError((error) => {
          console.error('🚨 gRPC Client Error:', error);

          throw error;
        }),
      ),
    );
  }

  async login(token: string) {
    return lastValueFrom(
      this.authService.loginUser({
        token,
      }),
    );
  }

  async deleteUser(deleteUserDto: { token: string } & DeleteUserDto) {
    return lastValueFrom(this.authService.deleteUser(deleteUserDto));
  }

  async signInWithKakaoAuthCode(kakaoAuthCode: string) {
    return lastValueFrom(
      this.authService.signInWithKakaoAuthCode({ code: kakaoAuthCode }),
    );
  }

  async signInWithKakaoUserInfo(
    signInKakaoUserInfoDto: SignInKakaoUserInfoDto,
  ) {
    return lastValueFrom(
      this.authService.signInWithKakaoUserInfo({
        ...signInKakaoUserInfoDto,
        kakaoAccount: signInKakaoUserInfoDto.kakao_account,
      }),
    );
  }
}
