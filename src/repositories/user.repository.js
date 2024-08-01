import { prisma } from '../../models/index.js';

//회원가입 시 이미 해당 유저 있는지 확인
export const findUserByUsername = async (username) => {
    return prisma.users.findFirst({
        where: { username },
    });
};

//회원가입 시 이미 해당 유저 있는지 확인
export const findUserByNickname = async (nickname) => {
    return prisma.users.findFirst({
        where: { nickname },
    });
};

//회원가입
export const createUser = async (username, password, nickname) => {
    return prisma.users.create({
        data: {
            username,
            password,
            nickname,
        },
    });
};

//refresh token db에 저장
export const updateUserRefreshToken = async (userId, refreshToken) => {
    return prisma.users.update({
        where: { userId },
        data: { refreshToken },
    });
};

//refresh token 이용하여 access token 재발급
export const findUserByRefreshToken = async (refreshToken) => {
    return prisma.users.findFirst({
        where: { refreshToken },
    });
};

//내 프로필 조회
export const findUserById = async (userId) => {
    return prisma.users.findFirst({
        where: { userId: +userId },
        select: {
            userId: true,
            username: true,
            nickname: true,
        },
    });
};