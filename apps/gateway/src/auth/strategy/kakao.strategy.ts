import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-kakao';

@Injectable()
export class KakaoStrategy extends PassportStrategy(Strategy, 'kakao') {
  constructor(
    // private readonly authService: AuthService,
    private readonly configService: ConfigService,
  ) {
    super({
      clientID: configService.getOrThrow<string>('KAKAO_REST_API_KEY'),
      callbackURL: configService.getOrThrow<string>('KAKAO_REDIRECT_URI'),
    });
  }

  validate(...args: any[]) {
    console.log(args);
    return args;
  }
}
