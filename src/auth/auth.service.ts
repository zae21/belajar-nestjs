import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaClient } from "@prisma/client";
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import e from "express";

@Injectable()
export class AuthService {
    constructor(private prisma:PrismaService){}

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
                user,
            }
        } catch (error) {
            throw error;
        }
    }
}