import { Controller, Get, Patch, UseGuards } from '@nestjs/common';
import { User } from '@prisma/client';
import { GetUser } from 'src/auth/decorator';
import { JwtGuard } from 'src/auth/guard';

@UseGuards(JwtGuard)
@Controller('users')
export class UserController {
    @Get('me')
    getMe(@GetUser() user: User){
        return {
            statusCode: 200,
            message: 'OK',
            user,
        };
    }

    @Patch('edit-data')
    editUser(@GetUser('id') userId: User) {
        return {
            statusCode: 200,
            message: 'OK',
            userId,
        };
    }
}
