import { Body, Controller, Get, Post, UseGuards, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { AuthGuard } from './guard/auth.guard';
import { LoginDto } from './dto/login.dto';
import { Request } from 'express';
import { Roles } from './decorators/roles.decorator';
import { RolesGuard } from './guard/roles.guard';
import { Role } from './enums/rol.enums';
import { Auth } from './decorators/auth.decorator';

interface RequestWithUser extends Request {
    user: { email: string, role: string }
}

@Controller('auth')
export class AuthController {

    constructor(
        private readonly authService: AuthService
    ) {}

    @Post('register')
    register(
        @Body()
        registerDto: RegisterDto
    ) {
        console.log(registerDto)
        return this.authService.register(registerDto)
    }

    @Post('login')
    login(
        @Body()
        loginDto: LoginDto
    ) {
        return this.authService.login(loginDto)
    }

    // @Get('profile')
    // @Roles(Role.ADMIN)
    // @UseGuards(AuthGuard, RolesGuard)
    // profile( @Req() req: RequestWithUser ) {
    //     return this.authService.profile(req.user)
    // }

    @Get('profile')
    @Auth(Role.USER)
    profile( @Req() req: RequestWithUser ) {
        return this.authService.profile(req.user)
    }
}
