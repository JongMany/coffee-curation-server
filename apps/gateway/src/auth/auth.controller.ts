import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Authorization } from './decorator/authorization.decorator';
import { RegisterUserDto } from './dto/register-user.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

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
}
