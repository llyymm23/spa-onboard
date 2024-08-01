import { signup, login, refreshToken, getUserProfile } from '../services/user.service.js';

//회원가입
export const signupController = async (req, res) => {
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

        const user = await signup(username, password, nickname);
        return res.status(201).json({ message: '회원가입이 완료되었습니다.', user });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
};

//로그인
export const loginController = async (req, res) => {
    const { username, password } = req.body;

    try {
        if (!username) {
            return res.status(400).json({ message: "사용자 이름은 필수값입니다." });
        }

        if (!password) {
            return res.status(400).json({ message: "비밀번호는 필수값입니다." });
        }

        const { accessToken, refreshToken } = await login(username, password);
        res.cookie('authorization', `Bearer ${accessToken}`, { httpOnly: true });
        res.cookie('refreshToken', refreshToken, { httpOnly: true });
        return res.status(201).json({ message: '로그인에 성공하였습니다.', token: { accessToken } });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
};

//refresh token으로 access token 재발급
export const refreshTokenController = async (req, res) => {
    const { refreshToken: token } = req.cookies;

    try {
        if (!token) {
            return res.status(401).json({ message: '로그인이 필요합니다.' });
        }

        const accessToken = await refreshToken(token);
        res.cookie('authorization', `Bearer ${accessToken}`, { httpOnly: true });
        return res.status(201).json({ message: '액세스 토큰이 갱신되었습니다.', token: { accessToken } });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
};

//프로필 조회
export const profileController = async (req, res) => {
    try {
        const { userId } = req.user;
        const user = await getUserProfile(userId);
        return res.status(201).json({ data: user });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
};