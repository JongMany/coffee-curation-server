import { Public } from '@app/common';
import {
  Body,
  Controller,
  Delete,
  Get,
  Post,
  Query,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { Authorization } from './decorator/authorization.decorator';
import { DeleteUserDto } from './dto/delete-user.dto';
import { RegisterUserDto } from './dto/register-user.dto';
import { SignInKakaoUserInfoDto } from './dto/signin-kakao-user-info.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  async registerUser(
    @Authorization() token: string,
    @Body() registerUserDto: RegisterUserDto,
  ) {
    const result = await this.authService.registerUser({
      token,
      ...registerUserDto,
    });
    return result;
  }

  @Public()
  @Post('login')
  async loginUser(@Authorization() token: string) {
    if (token === null) {
      throw new UnauthorizedException('토큰을 입력해주세요');
    }

    return this.authService.login(token);
  }

  @Delete('user')
  async deleteUser(
    @Authorization() token: string,
    @Body() deleteUserDto: DeleteUserDto,
  ) {
    if (token === null) {
      throw new UnauthorizedException('토큰을 입력해주세요');
    }

    return this.authService.deleteUser({ token, ...deleteUserDto });
  }

  // https://www.citefred.com/nestjs/14
  @Public()
  @Get('/kakao')
  @UseGuards(AuthGuard('kakao'))
  async redirecKakaoPage(@Req() request: Request) {
    // Passport의 AuthGuard에 의해 카카오 로그인 페이지로 리다이렉트
  }

  @Public()
  @Post('/register/kakao')
  async registerWithKakao(@Query('code') kakaoAuthCode: string) {
    const response =
      await this.authService.signInWithKakaoAuthCode(kakaoAuthCode);

    return {
      accessToken: response.accessToken,
      refreshToken: response.refreshToken,
    };
  }

  @Public()
  @Post('/login/kakao')
  async loginWithKakao(@Body() signInKakaoUserInfoDto: SignInKakaoUserInfoDto) {
    const response = await this.authService.signInWithKakaoUserInfo(
      signInKakaoUserInfoDto,
    );

    return {
      accessToken: response.accessToken,
      refreshToken: response.refreshToken,
    };
  }
}
