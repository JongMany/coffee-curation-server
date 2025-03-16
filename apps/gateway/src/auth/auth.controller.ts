import { Public } from '@app/common';
import {
  Body,
  Controller,
  Delete,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Authorization } from './decorator/authorization.decorator';
import { DeleteUserDto } from './dto/delete-user.dto';
import { RegisterUserDto } from './dto/register-user.dto';

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
}
