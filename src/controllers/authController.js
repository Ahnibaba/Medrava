import validator from "validator";
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import { parsePhoneNumberFromString } from "libphonenumber-js"
import bcrypt from "bcryptjs"

import { generateVerificationToken } from "../utils/generateVerificationToken.js";
import { generateTokens } from "../utils/generateTokens.js";
import { setCookies } from "../utils/setCookies.js";
import { sendVerificationEmail } from "../mailtrap/emails.js";
import prisma from "../prismaClient.js";
import getClientIp from "../utils/getClientIp";


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

        //This password criteria have to be sent to the frontend-dev also
        const passwordCriteria = [
            { label: "At least 8 characters", met: validData.password.length >= 8, weight: 1 },
            { label: "Contains uppercase letter", met: /[A-Z]/.test(validData.password), weight: 1 },
            { label: "Contains lowercase letter", met: /[a-z]/.test(validData.password), weight: 1 },
            { label: "Contains a number", met: /\d/.test(validData.password), weight: 1 },
            { label: "Contains special character", met: /[!@#$%^&*(),.?":{}|<>]/.test(validData.password), weight: 2 }
        ];

        const strengthScore = passwordCriteria.reduce(
            (score, criteria) => score + (criteria.met ? criteria.weight : 0), 0
        );

        const isStrongPassword = strengthScore >= 5

        //Get failed criteria for error message
        const failedCriteria = passwordCriteria.filter(criteria => !criteria.met).map(criteria => criteria.label);

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
                userAgent: validData.userAgent
            }

        });

        


        // I suggest the user be logged in immediately after registration
        //tokens
        const { accessToken, refreshToken } = generateTokens(user.id)

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

     const user = await prisma.provider.findUnique({
        where: {
          otp: code,
          otpExpiration: otpExpiration < Date.now()
        }
     })

   } catch (error) {
     console.log("Error in verifyEmail function", error);
     res.status(500).json({ message: "Server Error" })
   }

}




export { register }