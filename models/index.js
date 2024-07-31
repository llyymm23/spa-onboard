import { PrismaClient } from "@prisma/client";

export const prisma = new PrismaClient({
    log: ["query", "info", "warn", "error"],

    errorFormat: "pretty",
}); // PrismaClient 인스턴스를 생성합니다.