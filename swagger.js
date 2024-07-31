import swaggerUi from 'swagger-ui-express';
import swaggereJsdoc from 'swagger-jsdoc';

const options = {
    swaggerDefinition: {
        openapi: "3.0.0",
        info: {
            version: "1.0.0",
            title: "스파르타 온보딩 과제",
            description:
                "프로젝트 : 회원가입,로그인 구현",
        },
        servers: [
            {
                url: "http://localhost:3000",
            },
        ],
    },
    apis: ["./routers/*.js", "./routers/*.js"],
}
const specs = swaggereJsdoc(options)

export { swaggerUi, specs };