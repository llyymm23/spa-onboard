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

/**
 * @swagger
 * paths:
 *  /api/signup:
 *    post:
 *      summary: "회원가입"
 *      description: "새로운 사용자 회원가입"
 *      tags: [Users]
 *      responses:
 *        "201":
 *          description: 회원 가입 성공
 *        "400":
 *          description: username,password,nickname 입력 안 함
 *        "409":
 *          description: 이미 존재하는 사용자가 가입 시도
 *        "500":
 *          description: 이외의 예기치 못한 에러
 *          content:
 *            application/json:
 *              schema:
 *                type: object
 *                properties:
 *                      username: 
 *                          type: string
 *                      password:
 *                          type: string
 *                      nickname:
 *                          type: string
 */
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

/**
 * @swagger
 * paths:
 *  /api/login:
 *    post:
 *      summary: "로그인"
 *      description: "로그인하여 access token, refresh token 발급"
 *      tags: [Users]
 *      responses:
 *        "201":
 *          description: 로그인 성공
 *        "400":
 *          description: username,password 입력 안 함
 *        "401":
 *          description: 존재하지 않는 username이나 password로 로그인 시도
 *        "500":
 *          description : 이외의 예기치 못한 에러
 *          content:
 *            application/json:
 *              schema:
 *                type: object
 *                properties:
 *                      username: 
 *                          type: string
 *                      password:
 *                          type: string
 */
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

/**
 * @swagger
 * paths:
 *  /api/token:
 *    post:
 *      summary: "토큰 발급"
 *      description: "access token 만료기간이 15분이 지나 다시 refresh token으로 access token을 발급"
 *      tags: [Users]
 *      responses:
 *        "201":
 *          description: 토큰 발급 성공
 *        "401":
 *          description: refresh token도 만료되어 새로운 로그인 필요
 *        "403":
 *          description: 해당 refresh token을 가진 사용자 존재하지 않음
 *        "500":
 *          description: 이외의 예기치 못한 오류
 */
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
            return res.status(201).json({ message: '새로운 토큰을 발급하였습니다.', token: { accessToken } });
        });
    } catch (error) {
        return res.status(500).json({ error: '새로운 토큰 발급에 실패하였습니다.' });
    }
});

/**
 * @swagger
 * paths:
 *  /api/profile:
 *    get:
 *      summary: "프로필"
 *      description: "로그인한 사용자 정보 조회"
 *      tags: [Users]
 *      responses:
 *        "201":
 *          description: 프로필 조회 성공
 *        "500":
 *          description: 이외의 예기치 못한 오류
 *          content:
 *            application/json:
 *              schema:
 *                type: object
 *                properties:
 *                      username: 
 *                          type: string
 *                      nickname:
 *                          type: string
 */
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

        return res.status(201).json({ data: user });
    } catch (error) {
        return res.status(500).json({ message: "예기치 못한 에러가 발생하였습니다." });
    }
});

export default router;