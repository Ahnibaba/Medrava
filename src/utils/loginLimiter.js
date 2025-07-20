import rateLimit from "express-rate-limit";



const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // Limit each IP to 5 login attempt
    message: "Too many login attempts, please try again later",
    handler: (req, res) => {
        res.status(429).json({
            success: false,
            message: "Too many login attempts, please try again after 15 minutes"
        })
    }
})

export default loginLimiter