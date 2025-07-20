const getClientIp = (req) => {
    // Check for forwarded headers (if behind proxy like Nginx)
    const forwarded = req.headers["x-forwarded-for"]
    if(forwarded) {
        return forwarded.split(",")[0].trim();
    }

    // Fallback to direct connection IP
    return req.connection.remoteAddress || req.socket.remoteAddress
}


export default getClientIp