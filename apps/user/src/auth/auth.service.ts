import { status } from '@grpc/grpc-js';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { RpcException } from '@nestjs/microservices';
import { UserService } from '../user/user.service';
import { RegisterUserDto } from './dto/register-user.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async registerUser(registerUserDto: RegisterUserDto) {
    const { token: basicToken, ...userInformation } = registerUserDto;
    const { email, password } = this.parseBasicToken(basicToken);

    return this.userService.createUser({
      email,
      password,
      ...userInformation,
    });
  }

  private parseBasicToken(basicToken: string) {
    // Bearer $Token
    const basicTokenSplit = basicToken.split(' ');

    if (basicTokenSplit.length !== 2) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT, // gRPC의 400 Bad Request
        message: '토큰 포맷이 잘못되었습니다.',
      });
    }

    const [basic, token] = basicTokenSplit;

    if (basic.toLowerCase() !== 'basic') {
      throw new RpcException({
        code: status.INVALID_ARGUMENT, // gRPC의 400 Bad Request
        message: '토큰 포맷이 잘못되었습니다.',
      });
    }

    const decoded = Buffer.from(token, 'base64').toString('utf-8');

    // username:password
    const tokenSplit = decoded.split(':');
    if (tokenSplit.length !== 2) {
      throw new RpcException({
        code: status.INVALID_ARGUMENT, // gRPC의 400 Bad Request
        message: '토큰 포맷이 잘못되었습니다.',
      });
    }
    const [email, password] = tokenSplit;

    return {
      email,
      password,
    };
  }
}
