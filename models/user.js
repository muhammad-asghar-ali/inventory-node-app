import mongoose from "mongoose"
import bcrypt from "bcryptjs"

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "name is required"]
    },
    email: {
        type: String,
        required: [true, "email is required"],
        unique: true,
        trim: true,
        match: [
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/, "please add a valid email address"
        ]
    },
    password: {
        type: String,
        required: [true, "password is required"],
        minLength: [6, "password must be up to 6 characters"]
    },
    photo: {
        type: String,
        default: null
    },
    phone: {
        type: String,
        default: "+92"
    },
    bio: {
        type: String,
        maxLength: [250, "bio is must not more then 250 caharcters"],
        default: "bio"
    }
}, { timestamps: true })

userSchema.pre("save", function (next) {
    if(!this.isModified('password')) {
        return next()
    }

    const salt = bcrypt.genSaltSync(10);
    const hashPassword = bcrypt.hashSync(this.password, salt);

    this.password = hashPassword
    return next()
})

export default mongoose.model('user', userSchema)