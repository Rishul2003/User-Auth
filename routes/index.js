const { urlencoded } = require('express');
const express=require('express');
const router=express.Router();
const jwt=require('jsonwebtoken');
const User=require("../models/user");
const bcrypt=require('bcryptjs');
const nodemailer = require('nodemailer');
const path = require('path');


router.get('/',async function(req,res){
    try{
        const filePath = path.join(__dirname, '../views/home.html');
        return res.sendFile(filePath);
    }
    catch(err){ 
        return res.status(500).json(err);
    }
})
router.post('/register',async function(req,res){
    try{
        // console.log(req.body.email);
        const {username,email, password } = req.body;
        
        if ( !username||!email || !password) {
            return res.status(400).json({ error: 'Email Or password is Missing' });
        }
        let user=await User.findOne({email:email});
        if(user){
            return res.status(200).json("USER ALREADY PRESENT LOGIN TO CONTINUE");
        }
        let encryptpass=await bcrypt.hash(password, 12);
        let u1=await User.create({
            username:username,
            email:email,
            password:encryptpass
        });
        u1.save();
        return res.status(200).json("User Has Been created");

    }
    catch(err){
        return res.status(500).json(
            err
        )
    }
})


router.post('/login',async function(req,res){
    try{
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Missing parameters' });
        }
        console.log(username,password);
        let user=await User.findOne({username:username});
        if(!user){
            return res.status(409).json("Register first then login");
        }
        const checkpassword=await bcrypt.compare(password,user.password);
        console.log(checkpassword);
        if(!checkpassword){
            return res.status(402).json("WRONG PASSWORD");
            
        }
        const token = jwt.sign({ userId: user._id, username: user.username }, process.env.secret, { expiresIn: '2d' });
        // console.log(token);
        return res.status(200).json({
            message:"Successfullt Sign in,  Here is your token keep it safe",
            token:token
        });
    }
    catch(err){
        return res.status(500).json(err);
    }
})
router.post('/forget-password',async function(req,res){
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const resetToken = jwt.sign({ userId: user._id }, process.env.resetsecret, { expiresIn: '1h' });

        const resetLink = process.env.route+`/reset-password?token=${resetToken}`;

    
        const transporter = nodemailer.createTransport({
            service:'gmail',
    host:'smtp.google.com',
    port:process.env.nodemailer_port,
    secure:false,
    auth:{
        user:process.env.nodemailer_user,
        pass:process.env.nodemailer_password
    }
        });

        const mailOptions = {
            from:process.env.nodemailer_user ,
            to: user.email,
            subject: 'Password Reset',
            html: `Click the following link to reset your password: <a href="${resetLink}">${resetLink}</a>`,
        };

        await transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error(error);
                return res.status(500).json({ error: 'Failed to send reset email' });
            }
            console.log('Reset email sent:', info.response);
            return res.status(200).json({ message: 'Reset email sent successfully check your email this is the link which will be sent to email',link:resetLink  });
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal Server Error' });
    }
})

router.get('/reset-password',async function(req,res){
    try{
        const token=req.query.token;
        let verificate=jwt.verify(token, process.env.resetsecret);
        if(verificate){
            const filePath = path.join(__dirname, '../views/forgetpassword.html');
            return res.sendFile(filePath);
        }
    }
    catch(err){
        return res.status(401).json({messange:"INVALID PAGE",resetToken:token});
    }
})
router.post('/reset-password',async function(req,res){
    try{
        // const token=req.query.token;
        console.log(token);
        let verificate=jwt.verify(token, process.env.resetsecret);
        // console.log(req.body);
        if(verificate){
            if(!req.body.newPassword){
                return res.status(404).json("ENter new password");
            }
            let encryptpass=await bcrypt.hash(req.body.newPassword, 12);
            const user = await User.findById(verificate.userId);
            user.password=encryptpass;
            user.save();
            return res.json({
                message:"PASSWORD CHANGED SUCCESSFULLY"
            });
        }
    }
    catch(err){
        return res.status(401).json("INVALID Credentials");
    }
})

module.exports=router;