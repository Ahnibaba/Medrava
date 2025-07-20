import { response } from "express";
import { PASSWORD_RESET_REQUEST_TEMPLATE, PASSWORD_RESET_SUCCESS_TEMPLATE, VERIFICATION_EMAIL_TEMPLATE } from "./emailTemplates.js";
import { mailtrapClient, sender } from "./mailtrap.config.js";


export const sendVerificationEmail = async (email, verificationToken) =>  {
    const recipient = [{ email }]

    try {
       const response = await mailtrapClient.send({
        from: sender,
        to: recipient,
        subject: "Verify your email",
        html: VERIFICATION_EMAIL_TEMPLATE.replace("{verificationCode}", verificationToken),
        category: "Email Verification"
       }) 
       console.log("Email sent Successfully: ", response);
       
    } catch (error) {
      console.error("Error sending verification email: ", error);
      throw new Error(`Error sending verification email: ${error}`)
        
    }
    
}

export const sendWelcomeEmail = async (email, name) => {
    const recipient = [{ email }]

    try {
      const response = await mailtrapClient.send({
        from: sender,
        to: recipient,
        template_uuid: "4e1bf476-121a-4b76-a6a4-4d0bdd8631f7",
        template_variables: {
            "company_info_name": "Waow-X Group",
            "name": name
        }
      })  
      console.log("Welcome email sent successfully", response);
      
    } catch (error) {
       console.log("Error sending welcome email", error);
       throw new Error(`Error sending welcome email: ${error}`) 
    }
}

export const sendPasswordResetEmail = async (email, resetURL) => {
    const recipient = [{ email }]

    try {
      const response = await mailtrapClient.send({
        from: sender,
        to: recipient,
        subject: "Reset your password",
        html: PASSWORD_RESET_REQUEST_TEMPLATE.replace("{resetURL}", resetURL),
        category: "Password Reset"
      })
    } catch (error) {
      console.log("Reset Password email sent successfully: ", response);
      throw new Error(`Error sending reset password email: ${error}`)
    }
}


export const sendResetSuccessEmail = async (email) => {
    const recipient = [{ email }]
    try {
      const response = await mailtrapClient.send({
        from: sender,
        to: recipient,
        subject: "Password Reset Successful",
        html: PASSWORD_RESET_SUCCESS_TEMPLATE,
        category: "Password Reset"
      })
    } catch (error) {
        console.log("Password reset is successful: ", response);
        throw new Error(`Error resetting password: ${error}`)
        
    }
}
