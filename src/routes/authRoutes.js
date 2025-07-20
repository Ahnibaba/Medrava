import express from "express";
import { register, resendEmailVerificationCode, verifyEmail, login, logout, forgotPassword, resetPassword, checkAuth, refreshToken } from "../controllers/authController.js";
import loginLimiter from "../utils/loginLimiter.js";
import { protectRoute } from "../middleware/authMiddleware.js";


const router = express.Router()


router.post("/register", register)
router.post("/verify-email", verifyEmail)
router.post("/resend-code", resendEmailVerificationCode)
router.post("/login", loginLimiter, login)
router.post("/logout", logout)
router.post("/forgot-password", forgotPassword)
router.post("/reset-password/:token", resetPassword)
router.get("/refresh-token", refreshToken)
router.get("/profile", protectRoute, checkAuth)





export default router