import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { RegisterDto } from './dto/register.dto';

import * as bcryptjs from 'bcryptjs'
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
    constructor(private readonly usersService: UsersService) { }

    async register({ name, email, password }: RegisterDto) {
        const user = await this.usersService.findByEmail(email)
        if (user) throw new BadRequestException("El email ya está egistrado")
        return await this.usersService.create({
            name,
            email,
            password: await bcryptjs.hash(password, 10)
        })
    }

    async login({ email, password }: LoginDto) {
        const user = await this.usersService.findByEmail(email)
        if (!user) throw new UnauthorizedException("El email no esta registrado")

        const isValidPassword = await bcryptjs.compare(password, user.password)
        if (!isValidPassword) throw new UnauthorizedException("El password no es valido")
            
        return user
    }
}
