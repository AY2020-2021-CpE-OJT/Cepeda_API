const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');

const app = express();

// <<<<<<<<<<<<<<<< DATABASE >>>>>>>>>>>>>>>>> //
const localHost = 'mongodb://localhost/nukesite3';
const remoteHost = 'mongodb+srv://nobody:nuke3@local-cluster.ufwwa.mongodb.net/nukeTest';
mongoose.connect(localHost, {
	useNewUrlParser: true,
	useUnifiedTopology: true
});

const db = mongoose.connection;

db.once('open', () => {
	console.log("MongoDB Connected");
});
// <<<<<<<<<<<<<<<< MIDWARE >>>>>>>>>>>>>>>>> //
app.set('view-engine','ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());

// <<<<<<<<<<<<<<<< ROUTES >>>>>>>>>>>>>>>>> //

app.get('/', (req, res) => {
	res.send("THIS IS VERSION 4");
});
//  <<<<<<<<<<<<<<<< FORMS FOR LOGIN >>>>>>>>>>>>>>>>> //

//app.use(express.urlencoded);

const reroute = require('./routes/routes');
app.use('/',reroute);

// Starting server
const port = process.env.PORT || 2077;
app.listen(port, () => console.log(`Eavesdropping at Port ${port}`));