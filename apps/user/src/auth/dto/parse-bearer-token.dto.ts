import { IsBoolean, IsNotEmpty, IsString } from 'class-validator';

export class ParseBearerTokenDto {
  @IsString()
  @IsNotEmpty()
  token: string;

  @IsBoolean()
  @IsNotEmpty()
  isRefreshToken: false;
}
