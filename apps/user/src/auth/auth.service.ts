import { CustomRpcException } from '@app/common';
import { status } from '@grpc/grpc-js';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { v4 as uuidv4 } from 'uuid';

import { HttpService } from '@nestjs/axios';
import * as bcrypt from 'bcrypt';
import { firstValueFrom } from 'rxjs';
import { User } from '../user/entity/user.entity';
import { UserService } from '../user/user.service';
import { DeleteUserDto } from './dto/delete-user.dto';
import { ParseBearerTokenDto } from './dto/parse-bearer-token.dto';
import { RegisterUserDto } from './dto/register-user.dto';
import {
  KakaoAccount,
  SignInKakaoUserInfoDto,
} from './dto/signin-kakao-user.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
    private httpService: HttpService,
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

  async authenticate(email: string, password: string) {
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
    const isCorrectPassword = await this.comparePassowrd(
      password,
      user.password,
    );
    if (!isCorrectPassword) {
      throw new CustomRpcException({
        code: status.PERMISSION_DENIED, // gRPC의 400 Bad Request
        message: '존재하지 않는 유저입니다.',
        status: 404,
      });
    }
    return user;
  }
  private async comparePassowrd(requestPassword: string, userPassword: string) {
    return await bcrypt.compare(requestPassword, userPassword);
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
    const userId = data.sub;
    const user = await this.userService.findUserById(userId, {
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
    if (email !== user.email) {
      throw new CustomRpcException({
        code: status.PERMISSION_DENIED, // gRPC의 400 Bad Request
        message: '올바른 이메일을 입력해주세요',
        status: 404,
      });
    }
    const isCorrectPassword = await this.comparePassowrd(
      password,
      user.password,
    );
    if (!isCorrectPassword) {
      throw new CustomRpcException({
        code: status.PERMISSION_DENIED, // gRPC의 400 Bad Request
        message: '올바른 비밀번호를 입력해주세요',
        status: 404,
      });
    }
    return this.userService.deleteUser({
      userId: user.id,
      email: user.email,
    });
  }

  async signInWithKakaoAuthCode(kakaoAuthCode: string) {
    // Authorization Code로 Kakao API에 Access Token 요청
    const accessToken = await this.getKakaoAccessToken(kakaoAuthCode);

    // Access Token으로 Kakao 사용자 정보 요청
    const kakaoUserInfo = await this.getKakaoUserInfo(accessToken);

    // 카카오 사용자 정보를 기반으로 회원가입 또는 로그인 처리
    const user = await this.signUpWithKakao(
      kakaoUserInfo.id.toString(),
      kakaoUserInfo.kakao_account,
    );

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

  async signInWithKakaoUserInfo(kakaoUserInfo: SignInKakaoUserInfoDto) {
    // 카카오 사용자 정보를 기반으로 회원가입 또는 로그인 처리
    const kakaoEmail = kakaoUserInfo.kakaoAccount.email;
    const existingUser = await this.userService.findUserByEmail(kakaoEmail);
    if (!existingUser) {
      await this.signUpWithKakao(
        kakaoUserInfo.id.toString(),
        kakaoUserInfo.kakaoAccount,
      );
    }
    const user = await this.userService.findUserByEmail(kakaoEmail);

    if (!user) {
      throw new CustomRpcException({
        code: status.CANCELLED,
        message: '회원가입에 실패했습니다.',
        status: 404,
      });
    }

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

  async signUpWithKakao(
    kakaoId: string,
    kakaoAccount: KakaoAccount,
  ): Promise<User> {
    const kakaoUsername = kakaoAccount.profile.nickname;
    const kakaoEmail = kakaoAccount.email;

    // 카카오 프로필 데이터를 기반으로 사용자 찾기 또는 생성 로직을 구현
    const existingUser = await this.userService.findUserByEmail(kakaoEmail);
    if (existingUser) {
      return existingUser;
    }

    // 비밀번호 필드에 랜덤 문자열 생성
    const temporaryPassword = uuidv4(); // 랜덤 문자열 생성
    const hashedPassword = await this.hashPassword(temporaryPassword);

    // 새 사용자 생성 로직
    await this.userService.createUser({
      name: kakaoUsername,
      email: kakaoEmail,
      password: hashedPassword, // 해싱된 임시 비밀번호 사용
      profile: '',
      age: 0,
    });
    const newUser = await this.userService.findUserByEmail(kakaoEmail);
    if (!newUser) {
      throw new CustomRpcException({
        code: status.UNKNOWN,
        status: 500,
        message: '알 수 없는 에러가 발생했습니다.',
      });
    }
    return newUser;
  }

  async getKakaoAccessToken(code: string) {
    const formUrlEncoded = (x: Record<string, string>) =>
      Object.keys(x).reduce(
        (p, c) => p + `&${c}=${encodeURIComponent(x[c])}`,
        '',
      );

    const GET_TOKEN_URL = 'https://kauth.kakao.com/oauth/token';
    const GRANT_TYPE = 'authorization_code';

    const CLIENT_ID =
      this.configService.getOrThrow<string>('KAKAO_REST_API_KEY');
    const REDIRECT_URI =
      this.configService.getOrThrow<string>('KAKAO_REDIRECT_URI');

    const payload = {
      grant_type: GRANT_TYPE,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code,
      // client_secret:
    };

    // 1. 토큰 받기
    const { data: tokenInfo } = await firstValueFrom(
      this.httpService.post(GET_TOKEN_URL, null, {
        params: payload,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }),
    );
    return tokenInfo.access_token;
  }

  async getKakaoUserInfo(accessToken: string) {
    const GET_USER_INFO_URL = 'https://kapi.kakao.com/v2/user/me';
    const { data: userInfo } = await firstValueFrom(
      this.httpService.get(GET_USER_INFO_URL, {
        headers: { Authorization: `Bearer ${accessToken}` },
      }),
    );

    return userInfo;
  }

  private async hashPassword(password: string) {
    const round = this.configService.getOrThrow<number>('ROUND');
    const hashedPassword = await bcrypt.hash(password, round);
    return hashedPassword;
  }
}
