const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
	username: String,
	password: String,
	//profile_picture: 
});

module.exports = mongoose.model('User', userSchema);