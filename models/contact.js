const mongoose = require('mongoose');

const contactSchema = new mongoose.Schema({
	last_name: String,
	first_name: String,
    contact_numbers: [String]
	//profile_picture: 
});

module.exports = mongoose.model('Contact', contactSchema);