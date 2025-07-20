import express from "express";
import { register, resendEmailVerificationCode, verifyEmail, login } from "../controllers/authController.js";
import loginLimiter from "../utils/loginLimiter.js";


const router = express.Router()


router.post("/register", register)
router.post("/verify-email", verifyEmail)
router.post("/resend-code", resendEmailVerificationCode)
router.post("/login", loginLimiter, login)





export default router