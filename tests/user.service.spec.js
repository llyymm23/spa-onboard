import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { signup, login, refreshToken, getUserProfile } from '../src/services/user.service.js';
import { findUserByUsername, createUser, updateUserRefreshToken, findUserByRefreshToken, findUserById } from '../src/repositories/user.repository.js';

jest.mock('bcrypt');
jest.mock('jsonwebtoken');
jest.mock('../src/repositories/user.repository.js');

describe('User Service', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe('회원가입', () => {
        it('회원가입 성공', async () => {
            const username = 'testuser';
            const password = 'testpass';
            const nickname = 'testnick';

            findUserByUsername.mockResolvedValue(null);
            bcrypt.hash.mockResolvedValue('hashedpass');
            createUser.mockResolvedValue({ username, nickname });

            const result = await signup(username, password, nickname);

            expect(result).toEqual({ username, nickname });
            expect(bcrypt.hash).toHaveBeenCalledWith(password, 10);
            expect(createUser).toHaveBeenCalledWith(username, 'hashedpass', nickname);
        });

        it('이미 존재하는 사용자 이름으로 가입 시도', async () => {
            const username = 'testuser';
            const password = 'testpass';
            const nickname = 'testnick';

            findUserByUsername.mockResolvedValue({ username });

            await expect(signup(username, password, nickname)).rejects.toThrow('이미 존재하는 사용자입니다.');
        });
    });

    describe('로그인', () => {
        it('로그인 성공', async () => {
            const username = 'testuser';
            const password = 'testpass';
            const hashedPassword = 'hashedpass';
            const accessToken = 'accesstoken';
            const refreshToken = 'refreshtoken';

            findUserByUsername.mockResolvedValue({
                userId: 1,
                username,
                password: hashedPassword,
            });
            bcrypt.compare.mockResolvedValue(true);
            jwt.sign.mockImplementation((payload, secret, options) => {
                if (options.expiresIn === '15m') return accessToken;
                if (options.expiresIn === '7d') return refreshToken;
            });
            updateUserRefreshToken.mockResolvedValue();

            const result = await login(username, password);

            expect(result).toEqual({ accessToken, refreshToken });
            expect(bcrypt.compare).toHaveBeenCalledWith(password, hashedPassword);
            expect(jwt.sign).toHaveBeenCalledTimes(2);
            expect(updateUserRefreshToken).toHaveBeenCalledWith(1, refreshToken);
        });

        it('비밀번호가 일치하지 않는 경우', async () => {
            const username = 'testuser';
            const password = 'testpass';
            const hashedPassword = 'hashedpass';

            findUserByUsername.mockResolvedValue({
                userId: 1,
                username,
                password: hashedPassword,
            });
            bcrypt.compare.mockResolvedValue(false);

            await expect(login(username, password)).rejects.toThrow('비밀번호가 일치하지 않습니다.');
        });
    });

    describe('새로운 access token 발급', () => {
        it('새로운 토큰 발급 성공', async () => {
            const userId = 1;
            const token = 'validrefreshtoken';
            const accessToken = 'newaccesstoken';

            findUserByRefreshToken.mockResolvedValue({ userId });
            jwt.verify.mockReturnValue({ userId });
            jwt.sign.mockReturnValue(accessToken);

            const result = await refreshToken(token);

            expect(result).toEqual(accessToken);
            expect(findUserByRefreshToken).toHaveBeenCalledWith(token);
            expect(jwt.verify).toHaveBeenCalledWith(token, process.env.REFRESH_TOKEN_SECRET);
            expect(jwt.sign).toHaveBeenCalledWith({ userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
        });

        it('해당 refresh token을 가진 유저가 없을 때', async () => {
            const token = 'invalidrefreshtoken';

            findUserByRefreshToken.mockResolvedValue(null);

            await expect(refreshToken(token)).rejects.toThrow('해당 유저가 존재하지 않습니다.');
        });
    });

    describe('프로필 조회', () => {
        it('프로필 조회 성공', async () => {
            const userId = 1;
            const userProfile = { userId, username: 'testuser', nickname: 'testnick' };

            findUserById.mockResolvedValue(userProfile);

            const result = await getUserProfile(userId);

            expect(result).toEqual(userProfile);
            expect(findUserById).toHaveBeenCalledWith(userId);
        });
    });

});
