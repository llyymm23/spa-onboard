import express from 'express';
import { signupController, loginController, refreshTokenController, profileController } from '../controllers/user.controller.js';
import authMiddleware from '../middlewares/auth.middleware.js';

const router = express.Router();

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
router.post('/signup', signupController);

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
router.post('/login', loginController);

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
router.post('/token', refreshTokenController);

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
router.get('/profile', authMiddleware, profileController);

export default router;