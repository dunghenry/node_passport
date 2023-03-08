const mongoose = require('mongoose');
const connectDB = async () => {
    try {
        mongoose.set('strictQuery', false);
        await mongoose.connect(process.env.MONGODB_URL, {
            serverSelectionTimeoutMS: 5000,
            useNewUrlParser: true,
        });
        console.log('Connect MongoDB successfully');
    } catch (error) {
        console.log('Connect MongoDB failed');
        process.exit(1);
    }
};
process.on('SIGINT', async () => {
    console.log('Killed server');
    await mongoose.connection.close();
    process.exit(0);
});
module.exports = connectDB;
