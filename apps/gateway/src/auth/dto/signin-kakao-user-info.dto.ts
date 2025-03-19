import { IsNotEmpty, IsNotEmptyObject, IsNumber } from 'class-validator';

export class SignInKakaoUserInfoDto {
  @IsNumber()
  @IsNotEmpty()
  id: number;

  @IsNotEmptyObject()
  @IsNotEmpty()
  kakao_account: {
    profile: {
      nickname: string;
    };
    email: string;
  };
}
