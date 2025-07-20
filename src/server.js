import express from "express"
import crypto from "crypto"
import cookieParser from "cookie-parser"
import authRoutes from "./routes/authRoutes.js"


// console.log(crypto.randomBytes(32).toString("hex"));




const app = express()
const PORT = process.env.PORT || 5001


// middleware
app.use(express.json())
app.use(cookieParser())


// routes
app.use("/auth", authRoutes)



app.listen(PORT, () => {
    console.log(`Server starting at port ${PORT}`);
    
})