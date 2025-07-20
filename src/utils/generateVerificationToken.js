import crypto from "crypto";

export const generateVerificationToken = () => {
    return crypto.randomInt(100000, 999999).toString();
    
}