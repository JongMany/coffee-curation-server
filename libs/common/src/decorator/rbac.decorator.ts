import { Reflector } from '@nestjs/core';
import { Role } from '../types';

export const RBAC = Reflector.createDecorator<Role>();
