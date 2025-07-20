import jwt from "jsonwebtoken"
import { encryptId } from "./crypto.js"
import prisma from "../prismaClient.js"

export const generateTokens = async (userId, role, organisation_name) => {
    const accessToken = jwt.sign(
      { userId: encryptId(userId), role, organisation_name },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" }  
    )

    await prisma.refreshToken.deleteMany({
      where: { userId }
    })

    const refreshToken = jwt.sign(
        { userId:  encryptId(userId) },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: "7d" }
    )

    // Store in database
    const dbToken = await prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      }
    })

    return { accessToken, refreshToken }
}


export const verifyRefreshToken = async (token) => {
  try {
    // Verify JWT
    const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    const userId = decryptId(decoded.userId);

    // Check DB existence
    const dbToken = await prisma.refreshToken.findUnique({
      where: { token },
      include: { user: true }
    });

    if (!dbToken || dbToken.expiresAt < new Date()) {
      throw new Error('Invalid or expired refresh token');
    }

    return { userId, user: dbToken.user };
  } catch (error) {
    console.error('Refresh token verification failed:', error);
    throw error;
  }
};