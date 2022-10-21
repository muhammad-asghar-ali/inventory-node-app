import jwt from "jsonwebtoken"
import UserModel from "../models/user.js"
import { createError } from "../middlewares/errorHandler.js"

export const verifyToken = async (req, res, next) => {
    try {
        const token = req.cookies.token
        if (!token) {
           return next(createError(401, "You are not authorized"))
        }

        const data = jwt.verify(token, process.env.JWT)

        const user = await UserModel.findById(data.id).select("-password")

        if (!user) {
            return next(createError(401, "You are not authorized"))
        }
        req.user = user
        next()
    } catch (err) {
        next(err)
    }
} 