const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express()
const port = 8000
const privatKey = 'secret'

app.use(express.urlencoded({ extended: false }))
//make dumy database
const users = {
    romy: {
        name: 'romy'
    }
}
bcrypt.hash(('pass'), 10, (err, hash)=>{
    if(!err) users.romy.password = hash;
})

//authorization /privat page
const auth = (req, res, next) => {
    jwt.verify(users.romy.token, privatKey, (err, result) => {
        if(err){
             res.redirect('/denied');
        } else{
            next()
        }
    })
}

//login verified 
const verifyLogin = (username, password, fx) => {
    let user = users[username]
    if(user.token) return fx('you are allready login')
    if(!user) return fx('canot find user')
    bcrypt.compare(password, user.password, (err, result) => {
        if(!result){
            return fx(err)
        }
        return fx(null, user)
    })
}

//generate token
const genToken = (user) => {
    let token = jwt.sign({userID: user}, privatKey, {expiresIn: 30000})
    user.token = token
    return token
}
//login page
app.post('/login', (req, res) => {
    verifyLogin(req.body.username, req.body.password, (err, user) => {
        if(user){
            let token = genToken(user);
             res.json({
                 user: user,
                 token:token
             });
        } else {
             res.json(err);
        }
    })
});

app.get('/denied', (req, res) => {
    res.send("access Denied");
});

app.post('/privat',auth, (req, res) => {
    res.send("succes access privat connten");
});

app.listen(port, () => {
    console.log(`Server started on port`);
});