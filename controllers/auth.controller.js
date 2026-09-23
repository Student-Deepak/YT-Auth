import userModel from "../models/user.model.js";
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import config from "../config/config.js";
import sessionModel from "../models/session.model.js";

export async function register(req,res){

    const {username,email,password} = req.body;
    const isAlreadyRegistered = await userModel.findOne({
        $or:[
            {username},
            {email}
        ]
    })
    if(isAlreadyRegistered){
        return res.status(409).json({message:"Username or email already existed"})
    }
    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");

    const user = await userModel.create({
        username,
        email,
        password:hashedPassword
    })

    const refreshToken = jwt.sign({
        id:user._id
        },
        config.JWT_SECRET,
        {
            expiresIn:"7d"
        }
    )

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
    const session = await sessionModel.create({
        user:user._id,
        refreshTokenHash,
        ip:req.ip,
        userAgent:req.headers["user-agent"]
    })

    const accessToken = jwt.sign({
            id:user._id,
            sessionId:session._id
        },
        config.JWT_SECRET,
        {
            expiresIn:"15m"
        }
    )
    


    res.cookie("refreshToken",refreshToken,{
        httpOnly:true,
        secure:true,
        sameSite:"strict",
        maxAge:7 * 24 * 60 * 60 * 1000 // 7 days
    })

    res.status(201).json({message:"user registered successfully",
        user:{
            username:user.username,
            email:user.email
        },
        accessToken
    })

}

export async function login(req,res){
    const {email,password} = req.body;

    const user = await userModel.findOne({email})

    if(!user){
        return res.status(401).json({message:"Invalid email or password"})
    }

    const hashPassword = crypto.createHash("sha256").update(password).digest("hex");

    const isPasswordValid = (hashPassword ===user.password);

    if(!isPasswordValid){
        return res.status(401).json({message:"Invalid password"})
    }

    const refreshToken = jwt.sign({
        id:user._id
    },config.JWT_SECRET,
    {
        expiresIn:"7d"
    })
    
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    const session = await sessionModel.create({
        user:user._id,
        refreshTokenHash,
        ip:req.ip,
        userAgent:req.headers["user-agent"]
    })

    const accessToken = jwt.sign({
        id:user._id,
        sessionId:session._id
    },config.JWT_SECRET,{
        expiresIn:"15m"
    })

    res.cookie("refreshToken",refreshToken,{
        httpOnly:true,
        secure:true,
        sameSite:"strict",
        maxAge: 7 * 24 * 60 * 60 * 1000  // 7 days
    })

    res.status(200).json({
        message:"Logged in successfully",
        user:{
            username:user.username,
            email:user.email
        },
        accessToken,
    })
}

export async function getMe(req,res){
    const token = req.header('authorization').split(" ")[1];
    if(!token){
        return res.status(401).json({message:"Token not founded"});
    }
    // for using jwt 
    const decoded = jwt.verify(token,config.JWT_SECRET);
    // console.log(decode);

    const user = await userModel.findById(decoded.id);

    res.status(200).json({
        message:"user fetched successfully",
        user:{
            username:user.username,
            email:user.email,
        }
    })
}


export async function refreshToken(req, res) {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({ message: "Refresh token is not found" });
    }

    try {
        const decoded = jwt.verify(refreshToken, config.JWT_SECRET);
        const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

        const session = await sessionModel.findOne({
            refreshTokenHash,
            revoked: false
        });

        if (!session) {
            return res.status(401).json({
                message: "Invalid refresh token"
            });
        }

        // 1. Consistent payload matching register & login:
        const accessToken = jwt.sign(
            {
                id: decoded.id,
                sessionId: session._id
            },
            config.JWT_SECRET,
            {
                expiresIn: "15m"
            }
        );

        const newRefreshToken = jwt.sign(
            {
                id: decoded.id
            },
            config.JWT_SECRET,
            {
                expiresIn: "7d"
            }
        );

        const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");

        session.refreshTokenHash = newRefreshTokenHash;
        await session.save();

        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        // 2. Return the new accessToken to the client:
        return res.status(200).json({
            message: "Access token refreshed successfully",
            accessToken
        });

    } catch (err) {
        return res.status(401).json({ message: "Invalid or expired refresh token" });
    }
}


export async function logout(req,res){

    const refreshToken = req.cookies.refreshToken;

    if(!refreshToken){
        return res.status(400).json({message:"Refresh Token is not found"})
    }

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked:false
    })

    if(!session){
        return res.status(400).json({
            message:"Invalid refresh token"
        })
    }

    session.revoked = true;
    await session.save();

    res.clearCookie("refreshToken")
    res.status(200).json({
        message:"Logged out successfully"
    })
}


export async function logoutAll(req,res){
    const refreshToken = req.cookies.refreshToken;
    
    if(!refreshToken){
        return res.status(400).json({
            message:"Refresh Token Not Found"
        })
    }

    const decoded = jwt.verify(refreshToken,config.JWT_SECRET)

    await sessionModel.updateMany({
        user:decoded.id,
        revoked:false
    },{
        revoked:true
    })

    res.clearCookie("refreshToken")

    res.status(200).json({
        message:"Logged out from all devices seccessfully"
    })

}


