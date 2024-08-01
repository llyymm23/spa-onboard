import request from 'supertest';
import express from 'express';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { signupController, loginController, refreshTokenController, profileController } from '../src/controllers/user.controller.js';
import { signup, login, refreshToken, getUserProfile } from '../src/services/user.service.js';
import authMiddleware from '../src/middlewares/auth.middleware.js';

jest.mock('../src/services/user.service.js');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.post('/signup', signupController);
app.post('/login', loginController);
app.post('/token', refreshTokenController);
app.get('/profile', authMiddleware, profileController);

describe('User Controller', () => {
    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('POST 회원가입(/signup)', () => {
        it('회원가입 성공', async () => {
            signup.mockResolvedValue({ username: 'testuser', nickname: 'testnick' });

            const response = await request(app)
                .post('/signup')
                .send({ username: 'testuser', password: 'testpass', nickname: 'testnick' });

            expect(response.status).toBe(201);
            expect(response.body).toEqual({ message: '회원가입이 완료되었습니다.', user: { username: 'testuser', nickname: 'testnick' } });
        });

        it('사용자 이름 입력 안 한 경우', async () => {
            const response = await request(app)
                .post('/signup')
                .send({ password: 'testpass', nickname: 'testnick' });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe('사용자 이름은 필수값입니다.');
        });

        it('비밀번호 입력 안 한 경우', async () => {
            const response = await request(app)
                .post('/signup')
                .send({ username: 'testname', nickname: 'testnick' });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe('비밀번호는 필수값입니다.');
        });

        it('닉네임 입력 안 한 경우', async () => {
            const response = await request(app)
                .post('/signup')
                .send({ username: 'testname', password: 'testpass' });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe('닉네임은 필수값입니다.');
        });
    });

    describe('POST 로그인(/login)', () => {
        it('로그인 성공', async () => {
            login.mockResolvedValue({ accessToken: 'accesstoken', refreshToken: 'refreshtoken' });

            const response = await request(app)
                .post('/login')
                .send({ username: 'testuser', password: 'testpass' });

            expect(response.status).toBe(201);
            expect(response.body).toEqual({ message: '로그인에 성공하였습니다.', token: { accessToken: 'accesstoken' } });
        });

        it('사용자 이름 입력 안 한 경우', async () => {
            const response = await request(app)
                .post('/login')
                .send({ password: 'testpass' });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe('사용자 이름은 필수값입니다.');
        });

        it('비밀번호 입력 안 한 경우', async () => {
            const response = await request(app)
                .post('/login')
                .send({ username: 'testname' });

            expect(response.status).toBe(400);
            expect(response.body.message).toBe('비밀번호는 필수값입니다.');
        });
    });

    describe('POST 토큰 재발급(/token)', () => {
        it('새로운 access token 재발급 성공', async () => {
            refreshToken.mockResolvedValue('newaccesstoken');

            const response = await request(app)
                .post('/token')
                .set('cookie', ['refreshToken=validrefreshtoken']);

            expect(response.status).toBe(201);
            expect(response.body).toEqual({
                message: '액세스 토큰이 갱신되었습니다.',
                token: { accessToken: 'newaccesstoken' }
            });

            const cookies = response.headers['set-cookie'];
            const authorizationCookie = cookies.find(cookie => cookie.startsWith('authorization='));
            expect(authorizationCookie).toBe('authorization=Bearer%20newaccesstoken; Path=/; HttpOnly');
        });

        it('refresh token도 만료되어 로그인 필요한 경우', async () => {
            const response = await request(app)
                .post('/token');

            expect(response.status).toBe(401);
            expect(response.body.message).toBe('로그인이 필요합니다.');
        });
    });

    describe('GET 프로필 조회(/profile)', () => {
        it('프로필 조회 성공', async () => {
            getUserProfile.mockResolvedValue({ userId: 1, username: 'testuser', nickname: 'testnick' });

            const token = jwt.sign({ userId: 1 }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });

            const response = await request(app)
                .get('/profile')
                .set('Cookie', [`authorization=Bearer ${token}`]);

            expect(response.status).toBe(201);
            expect(response.body).toEqual({ data: { userId: 1, username: 'testuser', nickname: 'testnick' } });
        });
    });
});