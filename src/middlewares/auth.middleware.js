import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import env from 'dotenv';

env.config();

const prisma = new PrismaClient();

export default async function authenticateToken(req, res, next) {
    try {
        //user.router.js에서 로그인할 때 쿠키에 'authorization'이라는 키로 저장한 값 가져옴
        const { authorization } = req.cookies;

        if (!authorization) throw new Error('로그인이 필요합니다.');

        //공백을 기준으로 왼쪽 부분인 Bearer는 tokenType에, 저장된 jwt 값은 token에 저장
        const [tokenType, token] = authorization.split(' ');

        if (tokenType !== 'Bearer')
            throw new Error('토큰 타입이 Bearer 형식이 아닙니다.');

        if (!token) throw new Error('인증 정보가 올바르지 않습니다.');

        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        const userId = decodedToken.userId;

        if (!userId) throw new Error('인증 정보가 올바르지 않습니다.');

        const user = await prisma.users.findFirst({
            where: { userId: +userId },
        });

        if (!user) throw new Error('토큰 사용자가 존재하지 않습니다.');

        req.user = user;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ message: '토큰이 만료되었습니다.' });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(400).json({ message: '토큰이 조작되었습니다.' });
        }
        return res.status(400).json({ message: error.message });
    }
}