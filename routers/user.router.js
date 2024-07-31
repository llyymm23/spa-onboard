import express from 'express';
import { prisma } from '../models/index.js'
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import env from 'dotenv';
import authMiddleware from '../middlewares/auth.middleware.js';

env.config();

const router = express.Router();

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

//회원가입 
router.post('/signup', async (req, res, next) => {
    const { username, password, nickname } = req.body;

    try {
        if (!username) {
            return res.status(400).json({ message: "사용자 이름은 필수값입니다." });
        }

        if (!password) {
            return res.status(400).json({ message: "비밀번호는 필수값입니다." });
        }

        if (!nickname) {
            return res.status(400).json({ message: "닉네임은 필수값입니다." });
        }

        const isExistUser = await prisma.users.findFirst({
            where: { username },
        });

        if (isExistUser) {
            return res.status(409).json({ message: "이미 존재하는 사용자입니다." });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await prisma.users.create({
            data: {
                username,
                password: hashedPassword,
                nickname,
            },
        });

        return res.status(201).json({ message: '회원가입이 완료되었습니다.', user: { username: user.username, nickname: user.nickname } });
    } catch (error) {
        return res.status(500).json({ error: '예기치 못한 에러가 발생하였습니다.' });
    }
});

//로그인 
router.post('/login', async (req, res, next) => {
    const { username, password } = req.body;

    try {
        if (!username) {
            return res.status(400).json({ message: "사용자 이름은 필수값입니다." });
        }

        if (!password) {
            return res.status(400).json({ message: "비밀번호는 필수값입니다." });
        }

        const user = await prisma.users.findUnique({
            where: { username },
        });

        if (!user) {
            return res.status(401).json({ error: '해당 유저가 존재하지 않습니다.' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ error: '비밀번호가 일치하지 않습니다.' });
        }

        const accessToken = jwt.sign({ userId: user.userId }, ACCESS_TOKEN_SECRET, {
            expiresIn: '15m',
        });
        const refreshToken = jwt.sign({ userId: user.userId }, REFRESH_TOKEN_SECRET, {
            expiresIn: '7d',
        });

        //refresh token db에 저장
        await prisma.users.update({
            where: { userId: user.userId },
            data: { refreshToken },
        });

        // 쿠키에 해당하는 토큰값 전달
        res.cookie('authorization', `Bearer ${accessToken}`, { httpOnly: true });
        res.cookie('refreshToken', refreshToken, { httpOnly: true });

        return res.status(200).json({ message: '로그인에 성공하였습니다.', token: { accessToken } });
    } catch (error) {
        return res.status(500).json({ error: '예기치 못한 에러가 발생하였습니다.', details: error });
    }
});

//새로운 액세스 토큰 발급
router.post('/token', async (req, res, next) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({ message: '로그인이 필요합니다.' });
    }

    try {
        const user = await prisma.users.findFirst({
            where: { refreshToken },
        });

        if (!user) {
            return res.status(403).json({ message: '해당 유저가 존재하지 않습니다.' });
        }

        jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, decoded) => {
            if (err) {
                return res.status(403);
            }

            const accessToken = jwt.sign({ userId: user.userId }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
            res.cookie('authorization', `Bearer ${accessToken}`);
            return res.status(200).json({ message: '새로운 토큰을 발급하였습니다.', token: { accessToken } });
        });
    } catch (error) {
        return res.status(500).json({ error: '새로운 토큰 발급에 실패하였습니다.' });
    }
});

//내 정보 조회하기
router.get('/profile', authMiddleware, async (req, res, next) => {
    try {
        const { userId } = req.user;

        //인증에 성공하고, 비밀번호를 제외한 정보 반환
        const user = await prisma.users.findFirst({
            where: { userId: +userId },
            select: {
                userId: true,
                username: true,
                nickname: true,
            },
        });

        return res.status(200).json({ data: user });
    } catch (error) {
        return res.status(500).json({ message: "예기치 못한 에러가 발생하였습니다." });
    }
});

export default router;