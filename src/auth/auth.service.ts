import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { RegisterDto } from './dto/register.dto';

import * as bcryptjs from 'bcryptjs'
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(
        private readonly usersService: UsersService,
        private readonly jwtService: JwtService
    ) { }

    async register({ name, email, password }: RegisterDto) {
        const user = await this.usersService.findByEmail(email)
        if (user) throw new BadRequestException("El email ya está egistrado")
        await this.usersService.create({
            name,
            email,
            password: await bcryptjs.hash(password, 10)
        })
        return {name, email}
    }

    async login({ email, password }: LoginDto) {
        const user = await this.usersService.findByEmail(email)
        if (!user) throw new UnauthorizedException("El email no esta registrado")

        const isValidPassword = await bcryptjs.compare(password, user.password)
        if (!isValidPassword) throw new UnauthorizedException("El password no es valido")

        const payload = { email: user.email, role: user.role }
        return {
            access_token: await this.jwtService.signAsync(payload),
            email,
        }
    }

    async profile({ email, role }: { email: string, role: string }) {
        return await this.usersService.findByEmail(email)
    }
}
