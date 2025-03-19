import { IsNotEmpty, IsNotEmptyObject, IsNumber } from 'class-validator';

export class KakaoAccount {
  profile: {
    nickname: string;
  };
  email: string;
}

export class SignInKakaoUserInfoDto {
  @IsNumber()
  @IsNotEmpty()
  id: number;

  @IsNotEmptyObject()
  @IsNotEmpty()
  kakaoAccount: KakaoAccount;
}
