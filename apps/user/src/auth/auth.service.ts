import { CustomRpcException } from '@app/common';
import { status } from '@grpc/grpc-js';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { User } from '../user/entity/user.entity';
import { UserService } from '../user/user.service';
import { DeleteUserDto } from './dto/delete-user.dto';
import { ParseBearerTokenDto } from './dto/parse-bearer-token.dto';
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
      throw new CustomRpcException({
        status: 400,
        code: status.INVALID_ARGUMENT, // gRPC의 400 Bad Request
        message: '토큰 포맷이 잘못되었습니다.',
      });
    }

    const [basic, token] = basicTokenSplit;

    if (basic.toLowerCase() !== 'basic') {
      throw new CustomRpcException({
        status: 400,
        code: status.INVALID_ARGUMENT, // gRPC의 400 Bad Request
        message: '토큰 포맷이 잘못되었습니다.',
      });
    }

    const decoded = Buffer.from(token, 'base64').toString('utf-8');

    // username:password
    const tokenSplit = decoded.split(':');
    if (tokenSplit.length !== 2) {
      throw new CustomRpcException({
        status: 400,
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

  async parseBearerToken(parseBearerTokenDto: ParseBearerTokenDto) {
    const { token: bearerToken, isRefreshToken } = parseBearerTokenDto;
    const basicSplit = bearerToken.split(' ');
    if (basicSplit.length !== 2) {
      throw new CustomRpcException({
        status: 400,
        code: status.INVALID_ARGUMENT, // gRPC의 400 Bad Request
        message: '토큰 포맷이 잘못되었습니다.',
      });
    }

    const [bearer, token] = basicSplit;
    if (bearer.toLowerCase() !== 'bearer') {
      throw new CustomRpcException({
        status: 400,
        code: status.INVALID_ARGUMENT, // gRPC의 400 Bad Request
        message: '토큰 포맷이 잘못되었습니다.',
      });
    }

    try {
      const tokenSecret = this.configService.getOrThrow<string>(
        isRefreshToken ? 'REFRESH_TOKEN_SECRET' : 'ACCESS_TOKEN_SECRET',
      );
      const payload = await this.jwtService.verifyAsync(token, {
        secret: tokenSecret,
      });
      if (isRefreshToken) {
        if (payload.type !== 'refresh') {
          throw new CustomRpcException({
            status: 400,
            code: status.INVALID_ARGUMENT, // gRPC의 400 Bad Request
            message: 'Refresh Token을 입력해주세요',
          });
        }
      } else {
        if (payload.type !== 'access') {
          throw new CustomRpcException({
            status: 400,
            code: status.INVALID_ARGUMENT, // gRPC의 400 Bad Request
            message: 'Access Token을 입력해주세요',
          });
        }
      }
      return payload;
    } catch (e) {
      throw new CustomRpcException({
        status: 400,
        code: status.UNAUTHENTICATED, // gRPC의 400 Bad Request
        message: '토큰이 만료되었습니다.',
      });
    }
  }

  async login(rawToken: string) {
    const { email, password } = this.parseBasicToken(rawToken);
    const user = await this.authenticate(email, password);

    return {
      refreshToken: await this.issueToken({
        user,
        isRefreshToken: true,
      }),
      accessToken: await this.issueToken({
        user,
        isRefreshToken: false,
      }),
    };
  }

  private async authenticate(email: string, password: string) {
    const user = await this.userService.findUserByEmail(email, {
      id: true,
      email: true,
      password: true,
    });

    if (!user) {
      throw new CustomRpcException({
        code: status.PERMISSION_DENIED, // gRPC의 400 Bad Request
        message: '존재하지 않는 유저입니다.',
        status: 404,
      });
    }

    // validate email
    const isCorrectPassword = await bcrypt.compare(password, user.password);
    if (!isCorrectPassword) {
      throw new CustomRpcException({
        code: status.PERMISSION_DENIED, // gRPC의 400 Bad Request
        message: '존재하지 않는 유저입니다.',
        status: 404,
      });
    }
    return user;
  }

  private async issueToken(options: { user: User; isRefreshToken: boolean }) {
    const { user, isRefreshToken } = options;
    const refreshTokenSecret = this.configService.getOrThrow<string>(
      'REFRESH_TOKEN_SECRET',
    );
    const accessTokenSecret = this.configService.getOrThrow<string>(
      'ACCESS_TOKEN_SECRET',
    );

    return this.jwtService.signAsync(
      {
        // sub: user.id ?? user.sub,
        // role: user.role,
        sub: user.id,
        type: isRefreshToken ? 'refresh' : 'access',
      },
      {
        secret: isRefreshToken ? refreshTokenSecret : accessTokenSecret,
        expiresIn: '3600h',
      },
    );
  }

  async deleteUser(deleteUserDto: DeleteUserDto) {
    const { token: bearerToken, email, password } = deleteUserDto;
    const data = await this.parseBearerToken({
      token: bearerToken,
      isRefreshToken: false,
    });
    console.log(data);
  }
}
