require('dotenv').config();
const express=require('express');
const app=express();
const port=process.env.Port||8000;
const bodyParser=require('body-parser');
const cookieParser = require('cookie-parser');
const { urlencoded } = require('express');
const db=require('./config/mongoose')
app.use(bodyParser.json());
app.use(cookieParser());

app.use(urlencoded());
app.use(express.static('assets'));
app.set('views','./views');
app.set('view engine', 'html'); 
app.use('/',require('./routes'))


const server=app.listen(port,function(err){
    if(err){
        console.log(`Error in running the server  ${err}`)
    }
    console.log(`server is running on port ${port}`);
})

// GRa08a3ylE3EbpMm