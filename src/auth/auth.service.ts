import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { Tokens } from './types/tokens.type';
import { JwtPayload } from './types';
import { ConfigService } from '@nestjs/config';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private config: ConfigService,
  ) {}
  async signupLocal(dto: AuthDto): Promise<Tokens> {
    const hash = await argon.hash(dto.password);
    const user = await this.prisma.user
      .create({
        data: {
          email: dto.email,
          hash,
        },
      })
      .catch((err) => {
        if (err instanceof PrismaClientKnownRequestError) {
          if (err.code === 'P2002') {
            throw new ForbiddenException('Creditials incorrect');
          }
        }
        throw err;
      });

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }
  async signinLocal(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    if (!user) {
      throw new ForbiddenException('Access Denied');
    }

    const passwordMatches = await argon.verify(user.hash, dto.password);

    if (!passwordMatches) {
      throw new ForbiddenException('Access Denied');
    }

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async logout(userId: number): Promise<boolean> {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRt: {
          not: null,
        },
      },
      data: {
        hashedRt: null,
      },
    });

    return true;
  }

  async refresh(userId: number, rt: string): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user || !user.hashedRt) {
      throw new ForbiddenException('Access Denied');
    }

    const rMatches = await argon.verify(user.hashedRt, rt);
    if (!rMatches) throw new ForbiddenException('Access Denied');

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async updateRtHash(userId: number, rt: string): Promise<void> {
    const hash = await argon.hash(rt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const jwtPayload: JwtPayload = {
      sub: userId,
      email: email,
    };
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('AT_SECRET'),
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: this.config.get<string>('RT_SECRET'),
        expiresIn: '7d',
      }),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }
}
