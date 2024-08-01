import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import env from 'dotenv';
import { findUserByUsername, findUserByNickname, createUser, updateUserRefreshToken, findUserByRefreshToken, findUserById } from '../repositories/user.repository.js';

env.config();

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

//회원가입
export const signup = async (username, password, nickname) => {
    const existingUser = await findUserByUsername(username);
    if (existingUser) {
        throw new Error('이미 존재하는 사용자입니다.');
    }

    const existingNickname = await findUserByNickname(nickname);
    if (existingNickname) {
        throw new Error('이미 존재하는 닉네임입니다.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await createUser(username, hashedPassword, nickname);
    return { username: user.username, nickname: user.nickname };
};

//로그인
export const login = async (username, password) => {
    const user = await findUserByUsername(username);
    if (!user) {
        throw new Error('해당 유저가 존재하지 않습니다.');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        throw new Error('비밀번호가 일치하지 않습니다.');
    }

    const accessToken = jwt.sign({ userId: user.userId }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ userId: user.userId }, REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
    await updateUserRefreshToken(user.userId, refreshToken);

    return { accessToken, refreshToken };
};

//access token 재발급
export const refreshToken = async (token) => {
    const user = await findUserByRefreshToken(token);
    if (!user) {
        throw new Error('해당 유저가 존재하지 않습니다.');
    }

    const decoded = jwt.verify(token, REFRESH_TOKEN_SECRET);
    const accessToken = jwt.sign({ userId: decoded.userId }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });

    return accessToken;
};

//프로필 조회
export const getUserProfile = async (userId) => {
    const user = await findUserById(userId);
    return user;
};