import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService {
    constructor(
        private prisma:PrismaService, 
        private jwt:JwtService,
        private config:ConfigService
    ){}

    async signup(dto: AuthDto) {
        let hash = await argon.hash(dto.password.toString());
        try {
            let user = await this.prisma.user.create({
                data: {
                    username: dto.username.toString(),
                    password: hash,
                }
            });
            delete user.password;
            return {
                statusCode: 200,
                message: 'OK',
                user,
            }
        } catch (error) {
            if(error instanceof PrismaClientKnownRequestError && error.code === 'P2002') throw new ForbiddenException('Username is exist.');
            
            throw error;
        }
        

    }
    
    async signin(dto: AuthDto) {
        try {
            let user = await this.prisma.user.findFirst({
                where: {
                    username: dto.username.toString(),
                }
            });
            if(!user) throw new ForbiddenException('Credential is incorrect.');
            
            let matchPwd = await argon.verify(user.password, dto.password.toString());

            if(!matchPwd) throw new ForbiddenException('Credential is incorrect.');

            delete user.password;
            
            return {
                statusCode: 200,
                message: 'OK',
                token: await this.signToken(user.id, user.username),
            }
        } catch (error) {
            throw error;
        }
    }

    async signToken(userId:number, username: string): Promise<string> {
        let payload = {
            sub: userId,
            username,
        }
        const jwtSecret = this.config.get('JWT_SECRET')
        return this.jwt.signAsync(payload,{
            expiresIn: '15m', 
            secret: jwtSecret,
        });
    }

}