import express from "express"
import { changePassword, forgetPassword, getUserById, login, loginStatus, logout, register, resetPassword, updateUser } from "../controllers/user.js"
import { verifyToken } from "../middlewares/auth.js"
const router = express.Router()

router.post('/register', register)
router.post('/login', login)
router.get('/logout', logout)
router.get('/get-user', verifyToken, getUserById)
router.get('/login-status', loginStatus)
router.patch('/update-user', verifyToken, updateUser)
router.patch('/change-password', verifyToken, changePassword)
router.post('/forget-password', forgetPassword)
router.put('/reset-password/:resettoken', resetPassword)


export default router