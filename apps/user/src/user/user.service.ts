import { CustomRpcException } from '@app/common';
import { status } from '@grpc/grpc-js';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import { FindOptionsSelect, Repository } from 'typeorm';
import { CreateUserDto } from './dto/create-user.dto';
import { DeleteUserDto } from './dto/delete-user.dto';
import { User } from './entity/user.entity';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly configService: ConfigService,
  ) {}
  async createUser(createUserDto: CreateUserDto) {
    const { email, password, ...otherInformation } = createUserDto;
    const user = await this.findUserByEmail(email);

    if (user) {
      // throw new BadRequestException('이미 가입된 이메일입니다.');
      throw new CustomRpcException({
        code: status.INVALID_ARGUMENT,
        status: 400,
        message: '이미 가입된 이메일입니다.',
      });
    }
    const round = this.configService.getOrThrow<number>('ROUND');
    const hashedPassword = await bcrypt.hash(password, round);

    await this.userRepository.save({
      ...otherInformation,
      email,
      password: hashedPassword,
    });

    return this.userRepository.findOne({
      where: {
        email,
      },
    });
  }

  async findUserByEmail(
    email: string,
    selectOptions?: FindOptionsSelect<User>,
  ) {
    const user = await this.userRepository.findOne({
      where: {
        email,
      },
      select: selectOptions,
    });
    return user;
  }

  async deleteUser(deleteUserDto: DeleteUserDto) {}
}
