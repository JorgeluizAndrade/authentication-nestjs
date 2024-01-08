import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import { AuthDto } from './dto/auth.dto';
import { AuthService } from './auth.service';
import { Tokens } from './types';
import { Public, GetCurrentUser, GetCurrentUserId } from '../common/decorators';
import { RtGuard } from 'src/common/guards';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  signuplocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signupLocal(dto);
  }

  @Public()
  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  signinlocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.signinLocal(dto);
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logoutlocal(@GetCurrentUserId() userId: number): Promise<boolean> {
    return this.authService.logout(userId);
  }

  @Public()
  @UseGuards(RtGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshlocal(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser('refreshToken') rt: string,
  ): Promise<Tokens> {
    return this.authService.refresh(userId, rt);
  }
}
