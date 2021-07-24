const express = require('express');
const router = express.Router();
const Contact = require('../models/contact');
var mongodb = require("mongodb");
const { restart } = require('nodemon');
// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< SECURITY ADD ON INIT >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> //
const jwt = require('jsonwebtoken');
require('dotenv').config()
var key = process.env.SECURITY_KEY;
var qs = require('querystring');
const bcrypt = require('bcrypt');
const crypto = require('crypto');


// <<<<<<<<<<<<<<<< TESTS >>>>>>>>>>>>>>>>> //
router.get('/test', (req, res) => {
	res.send("test");
});
// <<<<<<<<<<<<<<<< ADD NEW >>>>>>>>>>>>>>>>> //
router.post('/new', verifyToken,  async (req, res) => {
	jwt.verify(req.token,key,async function(err,data){
		if(err){ 
			res.sendStatus(403);
			console.log("ADD NEW DEBUG: "+ req.token);
		} else {
			console.log("RUN ADD NEW");
			const newContact = new Contact(req.body);
			const savedContact = await newContact.save();
			res.json(savedContact);
		}
	})
});
// <<<<<<<<<<<<<<<< SEARCH VIA ID >>>>>>>>>>>>>>>>> //
router.get("/get/:id",verifyToken, async (req, res) => {
	jwt.verify(req.token,key,async function(err,data){
		if(err){ 
			res.sendStatus(403);
			console.log("SEARCH VIA ID DEBUG: "+ req.token);
		} else {
			console.log("RUN SEARCH VIA ID");
    		const foundContact = await Contact.findById({ _id: req.params.id });
    		res.json(foundContact);
		}
	})
});
// <<<<<<<<<<<<<<<< DELETE VIA ID >>>>>>>>>>>>>>>>> //
router.delete('/delete/:id',verifyToken, async (req, res) => {
	jwt.verify(req.token,key,async function(err,data){
		if(err){ 
			res.sendStatus(403);
			console.log("DELETE DEBUG: "+ req.token);
		} else {
			console.log("RUN DELETE VIA ID");
			const foundContact = await Contact.findByIdAndDelete({ _id: req.params.id });
    		res.json(foundContact);
		}
	})
});
// <<<<<<<<<<<<<<<< UPDATE VIA ID >>>>>>>>>>>>>>>>> //
router.patch('/update/:id',verifyToken, async (req, res) => {
	jwt.verify(req.token,key,async function(err,data){
		if(err){ 
			res.sendStatus(403);
			console.log("UPDATE DEBUG: "+ req.token);
		} else {
			console.log("RUN UPDATE VIA ID");
			const q = await Contact.updateOne({_id: req.params.id}, {$set: req.body});
			res.json(q);
		}
	})
});
// <<<<<<<<<<<<<<<< FIND ALL >>>>>>>>>>>>>>>>> //
router.get('/all', verifyToken,  async (req, res) => {
	jwt.verify(req.token,key,async function(err,data){
		if(err){ 
			res.sendStatus(403);
			console.log("FIND ALL DEBUG: "+ req.token);
		} else {
			console.log("RUN FIND ALL");
			const contact = await Contact.find();
			res.json(contact);
		}
	})
});
// <<<<<<<<<<<<<<<< SEARCH NAMES >>>>>>>>>>>>>>>>> //
router.get('/search/:via',verifyToken, async function(req,res){
	jwt.verify(req.token,key,async function(err,data){
		if(err){ 
			res.sendStatus(403);
			console.log("SEARCH NAMES DEBUG: "+ req.token);
		} else {
			console.log("RUN SEARCH NAMES");
    		var regex = new RegExp(req.params.via, 'i');  // 'i' makes it case insensitive
   			 return Contact.find( { $or: [ {first_name: regex} , {last_name: regex} ] }, function(err,contact){
        	return res.send(contact);
  		  });
		}
	})
});
// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< SECURITY ADD ON ROUTES >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> //
	
  async function compareEncrypted(toTest,encrypted){
	const validity = await  bcrypt.compare(toTest,encrypted);
	return (validity);
  }

  async function validityCheck(username,password){
	var validUser, validPass;
	await compareEncrypted(username, process.env.SECURED_NAME).then(value => { validUser = value; });
	await compareEncrypted(password, process.env.SECURED_PASS).then(value => { validPass = value; });
	if(validUser&&validPass){
		return true;
	} else {
		return false;
	}
}

// <<<<<<<<<<<<<<<< LOGIN SUPPOSEDLY >>>>>>>>>>>>>>>>> //
router.post('/login/:user/:password', async function(req,res){
	var user = { username: req.params.user, password: req.params.password };
	var valid;
	//console.log(user.username);
	await validityCheck(user.username,user.password).then(value => { valid=value; });

	if (valid) {
		res.json({token:jwt.sign({user},key)});
		console.log("TOKEN RETURNED");
	} else {
		res.json({token:"rejected"});
		console.log("Request Rejected");
	}
	
});

router.post('/login_nuke', async function(req,res){
	var user = { username: req.body.username, password: req.body.password };
	var valid;
	//console.log(user.username);
	await validityCheck(user.username,user.password).then(value => { valid=value; });

	if (valid) {
		res.json({token:jwt.sign({user},key)});
		console.log("TOKEN RETURNED");
	} else {
		res.json({token:"rejected"});
		console.log("Request Rejected");
	}
	
});

// <<<<<<<<<<<<<<<< SECURED ROUTE SUPPOSEDLY >>>>>>>>>>>>>>>>> //
router.get('/secure/:message',verifyToken, function(req,res){
	jwt.verify(req.token,key,function(err,data){
		if(err){ 
			res.sendStatus(403);
		} else {
			console.log("SECURE LOG: " + req.params.message);
			res.json({text: req.params.message, data: data });
		}
	})
});
// <<<<<<<<<<<<<<<< THIS FUNCTION CHECKS THE TOKEN >>>>>>>>>>>>>>>>> //
function verifyToken(req,res,next){
	const bearerHeader = req.headers["authorization"];
	if(typeof bearerHeader !== 'undefined'){
		const bearer = bearerHeader.split(" ");
		const bearerToken = bearer[1];
		req.token = bearerToken;
		next();
	} else {
		res.sendStatus(403);
	}
	
}

// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< PASSPORT SECURITY ADD ON ROUTES >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> //
router.get('/nuke', (req, res) => {
	res.render('index.ejs', {username: req.body.first_name});
});

router.post('/nuke', async (req, res) => {
	console.log("TEST");
	const newContact = new Contact(req.body);
	const savedContact = await newContact.save();
	res.json(savedContact);
	//return res.redirect('/all');
});

router.get('/login_nuke', (req, res) => {
	res.render('login.ejs');
});

/*
router.get('/register_nuke', (req, res) => {
	res.render('register.ejs');
});*/

router.post('/login_nuke_der', (req, res) => {
	
	bcrypt.hash(req.body.username, 10, (err, hash) => {
		console.log('Encrypted Username: '+hash);
	});
	bcrypt.hash(req.body.password, 10, (err, hash) => {
		console.log('Encrypted Password: '+hash);
	});

	bcrypt.compare(req.body.username, process.env.SECURED_NAME, function(err, res) {
		if(res){
			console.log('User is valid');
		} else {
			console.log('User is invalid');
		}
	});
	bcrypt.compare(req.body.password, process.env.SECURED_PASS, function(err, res) {
		if(res){
			console.log('Password is valid');
		} else {
			console.log('Password is invalid');
		}
	});
	//console.log(req.body.password);
	//console.log(req.body.name);
	//console.log(req);
	return res.redirect('/login_nuke');
});


router.post('/register_nuke', (req, res) => {
	console.log(req);
	console.log(req.body.name);
	//console.log(req);
	return res.redirect('/register_nuke');
});

router.post('/get_auth/:username/:password',async(req,res)=>{
	var auth = 'Basic ' + new Buffer.from(req.params.username+ ':' + req.params.password).toString('base64'); // Basic ZGVhZDo0bGl2ZQ==
	console.log(auth);
	res.json({"Authorization": auth});
});

router.post('/login_new',async (req,res) => {
	var decoded = ['',''];
	if(req.headers.authorization!=null){
		decoded = (Buffer.from((req.headers.authorization).split(" ").pop(), 'base64')).toString().split(':');
	};

	var user = { username: decoded[0], password: decoded[1] };
	var valid;
	await validityCheck(user.username,user.password).then(value => { valid=value; });

	if (valid) {
		res.json({token:jwt.sign({user},key)});
		console.log("TOKEN RETURNED");
	} else {
		res.json({token:"rejected"});
		console.log("Request Rejected");
	}
});

/*
function encrypt_data(){
	crypto.createCipheriv()
}*/
/*
const algorithm = 'aes-256-cbc';
const enkey = 'iQKAIzLzObCn522aw92EQB9EZECKAITC';
const iv = crypto.KeyObject

function encrypt(text) {
 let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(enkey), iv);
 let encrypted = cipher.update(text);
 encrypted = Buffer.concat([encrypted, cipher.final()]);
 return encrypted.toString('hex');
}

function decrypt(text) {
 let iv = Buffer.from(text.iv, 'hex');
 let encryptedText = Buffer.from(text.encryptedData, 'hex');
 let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(enkey), iv);
 let decrypted = decipher.update(encryptedText);
 decrypted = Buffer.concat([decrypted, decipher.final()]);
 return decrypted.toString();
}*/
/*
var hw = encrypt("Some serious stuff")
console.log(hw)
console.log(decrypt(hw))*/

/*
const jsonTransform = document.querySelector('#registry_data');
if(jsonTransform) {
	jsonTransform.addEventListener("submit",function(e){

	});
}*/


module.exports = router;