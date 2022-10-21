import mongoose from "mongoose"

const tokenSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: "user"
    },
    token: {
        type: String,
        required: true
    },
    createAt: {
        type: Date,
        required: true
    },
    expriesAt: {
        type: Date,
        required: true
    }
}, { timestamps: true })

export default mongoose.model('token', tokenSchema)