import crypto from "crypto";

export const generateVerificationToken = () => {
    return otp = crypto.randomInt(100000, 999999).toString();
    
}