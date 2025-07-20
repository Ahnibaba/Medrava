import validator from "validator";
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import { parsePhoneNumberFromString } from "libphonenumber-js"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"

import { generateVerificationToken } from "../utils/generateVerificationToken.js";
import { generateTokens, verifyRefreshToken } from "../utils/generateTokens.js";
import { setCookies } from "../utils/setCookies.js";
import { sendPasswordResetEmail, sendResetSuccessEmail, sendVerificationEmail, sendWelcomeEmail } from "../mailtrap/emails.js";
import prisma from "../prismaClient.js";
import getClientIp from "../utils/getClientIp.js";
import passwordStrengthMeter from "../utils/passwordStrengthMeter.js"
import { encryptId } from "../utils/crypto.js";


const window = new JSDOM('').window;
const purify = DOMPurify(window);

const register = async (req, res) => {
    const { email, organisation_name, phone, password } = req.body

    try {
        const ipAddress = getClientIp(req)

        const validData = {
            email: email?.trim(),
            organisation_name: organisation_name?.trim(),
            phone: phone?.trim(),
            password: password?.trim(),
            ipAddress,
            userAgent: req.headers["user-agent"] || "Unknown"
        }

        console.log(validData);


        if (!validData.email || !validData.organisation_name || !validData.phone || !validData.password) {
            return res.status(400).json({ message: "All fields are required" });
        }


        if (!validator.isEmail(validData.email)) {
            return res.status(400).json({ message: "Invalid email format" });
        }

        const existingUser = await prisma.provider.findUnique({
            where: {
                email: validData.email
            }
        })

        if (existingUser) {
            return res.status(409).json({ error: "Email already registered" })
        }


        try {
            const phoneNumber = parsePhoneNumberFromString(validData.phone);
            if (!phoneNumber || !phoneNumber.isValid) {
                return res.status(400).json({ error: "Invalid phone number" });
            }

            validData.phone = phoneNumber.formatInternational();

            const existingPhone = await prisma.provider.findUnique({
                where: {
                    phone: validData.phone
                }
            })

            if (existingPhone) {
                return res.status(409).json({ error: "Phone Number already registered" })
            }
        } catch (error) {
            return res.status(400).json({ message: "Invalid phone number format" });
        }

        validData.organisation_name = purify.sanitize(validData.organisation_name)

        const { isStrongPassword, passwordCriteria, failedCriteria } = passwordStrengthMeter(validData.password)

        if (!isStrongPassword) {
            return res.status(400).json({
                error: "Weak Password",
                requirements: passwordCriteria.map(c => (c.label)),
                failed: failedCriteria
            })
        }



        const genSalt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(validData.password, genSalt);

        const verificationToken = generateVerificationToken()


        const user = await prisma.provider.create({
            data: {
                email: validData.email,
                password: hashedPassword,
                organisation_name: validData.organisation_name,
                phone: validData.phone,
                otp: verificationToken,
                otpExpiration: new Date(Date.now() + 24 * 60 * 60 * 1000), //24 hours
                ipAddress: validData.ipAddress,
                userAgent: validData.userAgent,
                forgotOtpExpire: new Date(0)
            }

        });




        // I suggest the user be logged in immediately after registration
        //tokens
        const { accessToken, refreshToken } = await generateTokens(user.id, user.role, user.organisation_name)

        setCookies(res, accessToken, refreshToken)

        await sendVerificationEmail(user.email, verificationToken)

        console.log(user);

        res.status(201).json({
            success: true,
            message: "User created successfully",
            user
        })


    } catch (error) {
        console.log("Error in the register function in the authController: ", error);
        res.status(500).json({ message: "Server Error" });
    }
}


const verifyEmail = async (req, res) => {
    const { code } = req.body
    try {

        const user = await prisma.provider.findFirst({
            where: {
                otp: code,
                otpExpiration: {
                    gt: new Date()
                }
            }
        })

        if (!user) {
            return res.status(400).json({ success: false, message: "Invalid or expired verification code" })
        }
        const updatedUser = await prisma.provider.update({
            where: {
                id: user.id
            },
            data: {
                isVerified: true,
                otp: "",
                otpExpiration: new Date(0)
            }
        })

        await sendWelcomeEmail(updatedUser.email, updatedUser.name)

        res.status(200).json({
            success: true,
            message: "Email verified successfully",
            updatedUser
        })



    } catch (error) {
        console.log("Error in verifyEmail function", error);
        res.status(500).json({ message: "Server Error" })
    }

}


const resendEmailVerificationCode = async (req, res) => {
    const { email } = req.body

    try {
        if (!email) {
            return res.status(400).json({ message: "Email is required" })
        }

        const user = await prisma.provider.findUnique({
            where: {
                email
            }
        })
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" })
        }

        if (user.isVerified) {
            return res.status(400).json({ success: false, message: "Email is already verified" })
        }


        const updatedUser = await prisma.provider.update({
            where: {
                id: user.id
            },
            data: {
                otp: generateVerificationToken(),
                otpExpiration: new Date(Date.now() + 24 * 60 * 60 * 1000)
            }
        })

        await sendVerificationEmail(updatedUser.email, updatedUser.otp)


        res.status(200).json({
            success: true,
            message: "Verification email resent successfully"
        })





    } catch (error) {
        console.log("Error in resendVerification function", error);
        res.status(500).json({ message: "Server Error" })
    }


}

const login = async (req, res) => {
    const { email, password } = req.body


    try {
        const user = await prisma.provider.findUnique({
            where: {
                email
            }
        })
        if (!user) {
            return res.status(400).json({ message: "Invalid Credentials" })
        }

        const isPasswordValid = await bcrypt.compare(password, user.password)
        if (!isPasswordValid) {
            return res.status(400).json({ message: "Invalid Credentials" })
        }



        if (user.isDeleted) {
            return res.status(400).json({ message: "User has been deleted, do you want to restore your membership?" })
        }



        const { accessToken, refreshToken } = await generateTokens(user.id, user.role, user.organisation_name)



        setCookies(res, accessToken, refreshToken)

        if (!user.isVerified) {
            return (
                res.status(200).json({
                    success: true,
                    message: "Logged in successfully, check your mail to verify your account",
                    accessToken: accessToken

                })
            )

        } else {
            res.status(200).json({
                success: true,
                message: "Login Successful",
                accessToken
            })
        }





    } catch (error) {
        console.log("Error in login function", error);
        res.status(500).json({ message: "Server Error" })
    }


}


const logout = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken
        if (refreshToken) {
            const dbToken = await prisma.refreshToken.delete({
                where: { token: refreshToken },
                include: { user: true }
            })
            console.log(dbToken.user);

        }

        res.clearCookie("accessToken")
        res.clearCookie("refreshToken")

        res.status(200).json({ success: true, message: "Logged out successfully" })
    } catch (error) {
        console.log("Error in logout function", error);
        res.status(500).json({ message: "Server Error" })
    }
}


const forgotPassword = async (req, res) => {
    const { email } = req.body
    const resetToken = generateVerificationToken()
    try {
        const user = await prisma.provider.findUnique({
            where: {
                email
            }
        })

        if (!user) {
            return res.status(400).json({ success: false, message: "User not found" })
        }

        const updatedUser = await prisma.provider.update({
            where: {
                email: user.email
            },
            data: {
                forgotOtp: resetToken,
                forgotOtpExpire: new Date(Date.now() + 1 * 60 * 60 * 1000) // 1 hour
            }


        })
        await sendPasswordResetEmail(updatedUser.email, `${process.env.CLIENT_URL}/reset-password/${resetToken}`)


        res.status(200).json({ success: true, message: "Password reset link sent to your email" })


    } catch (error) {
        console.log("Error in forgotPassword function", error);
        res.status(500).json({ message: "Server Error" })
    }
}



const resetPassword = async (req, res) => {
    try {
        const { token } = req.params
        const { password } = req.body

        const user = await prisma.provider.findFirst({
            where: {
                forgotOtp: token, // Forgot password OTP, OTP sent when a use click on forgot password requesting a password reset
                forgotOtpExpire: {
                    gt: new Date(Date.now())
                }
            }

        })

        if (!user) {
            return res.status(400).json({ success: false, message: "Invalid or expired reset token" })
        }

        const trimmedPassword = password.trim();
        if (!trimmedPassword) throw new Error('Password cannot be empty');

        const { isStrongPassword, passwordCriteria, failedCriteria } = passwordStrengthMeter(trimmedPassword)

        if (!isStrongPassword) {
            return res.status(400).json({
                error: "Weak Password",
                requirements: passwordCriteria.map(c => (c.label)),
                failed: failedCriteria
            })
        }


        const salt = await bcrypt.genSalt(10)
        const hashedPassword = await bcrypt.hash(trimmedPassword, salt)


        const updatedUser = await prisma.provider.update({
            where: {
                id: user.id
            },
            data: {
                password: hashedPassword,
                forgotOtp: "",
                forgotOtpExpire: new Date(0)

            }
        })

        await sendResetSuccessEmail(updatedUser.email)
        res.status(200).json({ success: true, message: "Password reset successful" })

    } catch (error) {
        console.log("Error in resetPassword function", error);
        res.status(500).json({ message: "Server Error" })
    }
}


const refreshToken = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken
        console.log(refreshToken);
        

        if (!refreshToken) {
            return res.status(401).json({ message: "No refresh token provided" })
        }

        const { userId, user } = await verifyRefreshToken(refreshToken)

        console.log(user);
        

        const accessToken = jwt.sign(
            {
                id: encryptId(user.id),
                role: user.role,
                organisation_name: user.organisation_name
            },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: "15m" }
        )


        res.cookie("accessToken", accessToken, {
            httpOnly: true, //prevent XSS attacks, cross site scripting attack
            secure: process.env.NODE_ENV === "production",
            sameSite: "None", // prevents CSRF attack, cross-site request forgery
            maxAge: 15 * 60 * 1000, // 15 minutes


        })

        res.status(200).json({ message: "Token refreshed successfully" })

    } catch (error) {
        console.log("Error in refreshToken function", error);
        res.status(500).json({ success: false, error: error.message })
    }
}


const checkAuth = async (req, res) => {
    const { userId } = req
    try {
        const user = await prisma.provider.findUnique({
  where: {
    id: userId
  },
  select: {
    id: true,
    email: true,
    organisation_name: true,
    phone: true,
    isVerified: true,
  }
});
        if (!user) {
            return res.status(400).json({ success: false, error: "User not found" })
        }

        res.status(200).json({ success: true, user })

    } catch (error) {
        console.log("Error in checkAuth function", error.message);
        res.status(500).json({ success: false, error: error.message })
    }
}


export { register, verifyEmail, resendEmailVerificationCode, login, logout, forgotPassword, resetPassword, refreshToken, checkAuth }