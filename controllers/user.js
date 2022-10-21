import jwt from "jsonwebtoken"
import bcrypt from "bcryptjs"
import crypto from "c"
import UserModel from "../models/user.js"
import TokenModel from "../models/token.js"
import { createError } from "../middlewares/errorHandler.js"
import sendEmail from "../utiles/sendMail.js"

const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT, { expiresIn: "1d" })
}

export const register = async (req, res, next) => {
    try {
        const { name, email, password } = req.body
        if (!name || !email || !password) {
            return next(createError(400, "name or email or password is missing"))
        }
        if (password.length < 6) {
            return next(createError(400, "password is less then 6 characters"))
        }

        const alreadyExist = await UserModel.findOne({ email: email })
        if (alreadyExist) {
            return next(createError(409, "password is less then 6 characters or more then 23 charaters"))
        }

        const user = await UserModel.create({
            name,
            email,
            password
        })
        const token = generateToken(user._id)

        const { password: p, ...info } = user._doc
        res.cookie("token", token, {
            // path: '/',
            httpOnly: true,
            expries: new Date(Date.now() + 1000 * 86400),
            // sameSite: "none",
            // secure: true
        }).status(201).json({
            message: "User registered",
            user: { ...info }
        })

    } catch (err) {
        next(err)
    }
}

export const login = async (req, res, next) => {
    try {
        const { email, password } = req.body

        if (!email || !password) {
            return next(createError(400, "email or password is missing"))
        }

        const user = await UserModel.findOne({ email: email })
        if (!user) {
            return next(createError(404, "user not found with this email"))
        }

        const isCorrectPasswrod = bcrypt.compare(password, user.password)

        if (!isCorrectPasswrod) {
            return next(createError(400, "invalid cridentials"))
        }
        const token = generateToken(user._id)
        const { password: p, ...info } = user._doc

        res.cookie("token", token, {
            path: '/',
            httpOnly: true,
            expries: new Date(Date.now() + 1000 * 86400),
            sameSite: "none",
            secure: true
        }).status(200).json({
            message: "User login",
            user: { ...info }
        })
    } catch (err) {
        next(err)
    }
}

export const logout = async (req, res, next) => {
    try {
        res.cookie("token", "", {
            path: '/',
            httpOnly: true,
            expries: new Date(0),
            sameSite: "none",
            secure: true
        })
        res.status(200).json({
            message: "User logout",
            user: null
        })
    } catch (err) {
        next(err)
    }
}

export const getUserById = async (req, res, next) => {
    try {
        const id = req.user._id
        if (!id) {
            return next(createError(400, "id is missing"))
        }

        const user = await UserModel.findById(id)
        if (!user) {
            return next(createError(400, "user not found"))
        }

        const { password, ...info } = user._doc
        res.status(200).json({
            message: "User data",
            user: { ...info }
        })
    } catch (err) {
        next(err)
    }
}

export const loginStatus = async (req, res, next) => {
    try {
        const token = req.cookies.token
        if (!token) {
            return next(createError(401, "You are not authorized"))
        }

        const data = jwt.verify(token, process.env.JWT)

        if (!data) {
            return res.status(400).json(false)
        }
        return res.status(200).json(true)
    } catch (err) {
        next(err)
    }
}

export const updateUser = async (req, res, next) => {
    try {
        const id = req.user._id
        const data = req.body
        if (!id) {
            return next(createError(400, "id is missing"))
        }

        const user = await UserModel.findById(id)

        if (!user) {
            return next(createError(400, "user not found"))
        }

        const { name, email, photo, phone, bio } = user

        user.email = email
        user.name = data.name || name
        user.photo = data.photo || photo
        user.phone = data.phone || phone
        user.bio = data.bio || bio

        const updateUser = await user.save()
        res.status(200).json({
            message: "User updated",
            user: {
                email: updateUser.email,
                name: updateUser.name,
                photo: updateUser.photo,
                phone: updateUser.phone,
                bio: updateUser.bio
            }
        })

    } catch (err) {
        next(err)
    }
}

export const changePassword = async (req, res, next) => {
    try {
        const id = req.user._id
        const { oldPassword, password } = req.body
        if (!id) {
            return next(createError(400, "id is missing"))
        }

        const user = await UserModel.findById(id)

        if (!user) {
            return next(createError(400, "user not found"))
        }

        if (!oldPassword || !password) {
            return next(createError(400, "please enter old or new password"))
        }

        const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password)

        if (user && passwordIsCorrect) {
            user.password = password
            await user.save()
            res.status(200).json({ message: "password changed" })
        } else {
            return next(createError(400, "old password is incorrect"))
        }
    } catch (err) {
        next(err)
    }
}

export const forgetPassword = async (req, res, next) => {
    try {
        const { email } = req.body
        if (!email) {
            return next(createError(400, "email is missing"))
        }

        const user = await UserModel.findOne({ email: email })

        if (!user) {
            return next(createError(400, "user not found"))
        }

        let token = await TokenModel.findOne({ userId: user._id })
        if (token) {
            await token.deleteOne()
        }

        let resetToken = crypto.randomBytes(32).toString("hex") + user._id

        const hashedToken = crypto.createHash("sha256").update(resetToken).digest("hex")

        await TokenModel.create({
            userId: user._id,
            token: hashedToken,
            createAt: Date.now(),
            expriesAt: Date.now() + 30 * (60 * 1000)
        })

        const resetUrl = `${process.env.FRONT_END_URL}/reset-password/${resetToken}`

        const message = `
            <h2>Hello ${user.name}</h2>
            <p>please click on below url to reset password</p>
            <p>this reset link is valid for 30 mintues.</p>

            <a href=${resetUrl} clicktracking=off>${resetUrl}</a>

            <p>Regards</p>
            <p>Dev Team</p>
        `

        const subject = "Password Reset Request"
        const send_to = user.email
        const send_from = process.env.EMAIL_USER

        const emailSent = await sendEmail(subject, message, send_to, send_from)
        if (emailSent) {
            res.status(200).json({ message: "password changed" })
        } else {
            return next(createError(400, "email is not sent, please try again"))
        }
    } catch (err) {
        next(err)
    }
}

export const resetPassword = async (req, res, next) => {
    try {
        const { resettoken } = req.params
        const { password } = req.body

        if(!resettoken) {
            return next(createError(400, "bad request: missing reset token"))
        }

        if(!password) {
            return next(createError(400, "bad request: missing reset password"))
        }

        const hashedToken = crypto.createHash("sha256").update(resettoken).digest("hex")

        const userToken = await TokenModel.findOne({
            token: hashedToken,
            expriesAt: { $gt: Date.now() }
        })

        if(!userToken) {
            return next(createError(400, "invalid or expired token"))
        }

        const user = await UserModel.findOne({_id: userToken.userId})
        if(!user) {
            return next(createError(404, "user not found"))
        }
        user.password = password
        await user.save()
        res.status(200).json({
            message: "Password reset successfully, please login."
        })
    } catch (err) {
        next(err)
    }
}