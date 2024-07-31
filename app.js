import express from "express";
import cookieParser from "cookie-parser";
import UsersRouter from "./routers/user.router.js";
import { swaggerUi, specs } from './swagger.js';

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(cookieParser());

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

app.use("/api", [UsersRouter]);

app.listen(PORT, () => {
    console.log(PORT, "포트로 서버가 열렸어요!");
});