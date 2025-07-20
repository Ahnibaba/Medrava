import express from "express"
import crypto from "crypto"

//console.log(crypto.randomBytes(64).toString("hex"));



const app = express()
const PORT = process.env.PORT || 5001


app.use(express.json())



app.listen(PORT, () => {
    console.log(`Server starting at port ${PORT}`);
    
})