const { Schema, models, model } = require('mongoose');
const userSchema = new Schema(
    {
        name: {
            type: String,
        },
        email: {
            type: String,
            required: true,
            trim: true,
            unique: true,
        },
        password: {
            type: String,
        },
        googleId: {
            type: String,
        },
        facebookId:{
            type: String
        }
    },
    {
        timestamps: true,
    },
);
const User = models.User || model('User', userSchema);
module.exports = User;
