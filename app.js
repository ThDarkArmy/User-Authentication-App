const express = require('express')
const bcrypt = require('bcryptjs')
const mongoose = require('mongoose')
const hbs = require('hbs')
const passport = require('passport')
const bodyParser = require('body-parser')
const session = require('express-session')
const flash  = require('connect-flash')
const {check, validationResult} = require('express-validator')

const User = require('./models/user.js')

const app = express()

const {
    PORT = 3000,
    NODE_ENV = 'development',
    SESS_NAME = 'sid',
    SESS_SECRET='dfgvhgvh',
    SESS_LIFETIME = 1000*60*60*2
    
} = process.env

mongoose.connect('mongodb://localhost:27017/loginapp',{useNewUrlParser: true, useUnifiedTopology : true, useCreateIndex: true}).then(()=>{
    console.log("connected to database!")
}).catch((error)=>{
    console.log('Unable to connected to the database!')
})


app.set('view engine', 'hbs')
app.use(express.static('public'))
app.use(bodyParser.urlencoded({extended:true}))
app.use(bodyParser.json())
hbs.registerPartials(__dirname + '/views/partials')

// Express session
app.use(
    session({
      secret: SESS_SECRET,
      resave: true,
      saveUninitialized: true,
      cookie: {
          maxAge: SESS_LIFETIME,
          sameSite: true,
          secure: 'production'
      }
    })
  )

const redirectLogin = (req, res, next)=>{
    if(!req.session.userId){
        res.redirect('/user/login')
    }else{
        next()
    }
}

const redirectHome = (req, res, next)=>{
    if(!req.session.userId){
        res.redirect('/')
    }else{
        next()
    }
}


//connect flash
app.use(flash())

app.get('/', (req, res)=>{
    res.render('index')
})

app.get('/user/login', (req, res)=>{
    res.render('login')
})

app.get('/user/register', (req, res)=>{
    res.render('register')
})

app.get('/user',(req , res)=>{
    res.json(User.find({}))
})


//Register 
 app.post('/user/register',redirectHome, (req, res)=>{
    
    const user = new User({
        name : req.body.name,
        email: req.body.email,
        mobile: req.body.number,
        password : req.body.password
    })

    if(user.name && user.email && user.mobile && user.password){
        var loop = true;
        User.findOne({email: req.body.email}).then(user=>{
            if(user){
                console.log('User already exists!')
                loop=false;
                return res.render('register',{msg:'User Already Exists!'})
            }else{
                try{
                    const newUser = new User({
                        name : req.body.name,
                        email: req.body.email,
                        mobile: req.body.number,
                        password : req.body.password
                    })
                    
                    //hashing the password
                    bcrypt.genSalt(4,(err, salt)=>bcrypt.hash(newUser.password, salt, (err, hash)=>{
                        if(err) throw err
                        newUser.password=hash
                        newUser.save().then(()=>{
                            console.log('Successfully Saved!')
                            res.redirect('login')
                        }).catch((error)=>{
                            console.log('Error in saving data in the database!', error)
                            res.render('register',{msg: 'Authentication error!'})
                        })   
                    })) 
                }catch(e){}
            }
        })    
    }else{
        console.log('Please provide all the necessary information!')
        res.render('register',{msg:'Perhapes you have missed something! Please provide all the necessary information!'})
    }
    
 })

 //Login User
 app.post('/user/login',redirectHome, (req, res)=>{
     if(req.body.email && req.body.password){
        var {email, password} = req.body
         try{
            
            bcrypt.genSalt(4,(err, salt)=>bcrypt.hash(password, salt, (err, hash)=>{
            if(err) throw err
            password=hash
        })) 
         }catch(e){}
        
         User.findOne({email : req.body.email}).then((user)=>{
            bcrypt.compare(password, user.password,(err, isMatch)=>{
                if(err){
                    console.log('Password is not correct!')
                    res.render('login',{msg: 'Password is not correct!'})
                }else{
                    console.log('Logged in successfully!')
                    res.session.userId=user.id
                    res.redirect('/')
                }
            })
         }).catch((err)=>{
             console.log("User with this mail doesn't exists",err)
             res.render('login',{msg: "User with this email doesn't exists"})
         })
     }else{
         console.log("Please enter the credentials!")
         res.render('login',{msg: 'Please enter the credentials!'})
     }

 })

 app.get('/user/logout',redirectLogin, (req, res)=>{
    req.session.destroy(err=>{
        if(err){
            return res.redirect('/home')
        }

        res.clearCookie(SESS_NAME)
        res.redirect('/user/login')
    })
 })




app.listen(PORT, ()=>console.log('Running on port : '+PORT))
