import { BaseTable, Role } from '@app/common';
import { Exclude } from 'class-transformer';
import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class User extends BaseTable {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({
    unique: true,
  })
  email: string;

  @Column()
  name: string;

  @Column()
  age: number;

  @Column()
  profile: string;

  @Column({
    select: false,
  })
  @Exclude({
    toPlainOnly: true,
  })
  password: string;

  @Column({
    type: 'enum',
    enum: Role,
    default: Role.user,
  })
  role: Role;
}
