import { USER_SERVICE, UserMicroservice } from '@app/common';
import { AUTH_MICROSERVICE } from '@app/common/constants/microservices';
import { Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { ClientGrpc } from '@nestjs/microservices';
import { catchError, lastValueFrom } from 'rxjs';
import { RegisterUserDto } from './dto/register-user.dto';

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

  login(token: string) {
    return lastValueFrom(
      this.authService.loginUser({
        token,
      }),
    );
  }
}
