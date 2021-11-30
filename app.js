/* write your server code here */
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { json } = require('express');
const saltRounds = bcrypt.genSaltSync(10);
const app = express();
app.use(express.json());

const USERS = [] 
const INFORMATION = []
const REFRESHTOKENS = []

app.post('/users/register', (req, res, next)=>{
    let admin;
    for(let i = 0; i < INFORMATION.length; i++) {
        if(INFORMATION[i].email === req.body.email) {
            res.status(409).send("user already exists");
            res.end();
        }
    }
    if(req.body.password === 'Rc123456!'){
         admin = false;
    }
    else {
        admin = true;
    }
    const password = bcrypt.hashSync(req.body.password, saltRounds);
    USERS.push({ email: req.body.email, name: req.body.name, password: password, isAdmin: admin })
    INFORMATION.push({email: req.body.email, info: `${req.body.name} info`})
    res.status(201).send("Register Success");
})

app.post('/users/login', (req, res ,next)=>{
    let target;
    for(let i = 0; i < USERS.length; i++) {
        if(USERS[i].email === req.body.email && !bcrypt.compare(req.body.password, USERS[i].password)) {
            res.status(403).send("User or Password incorrect");
            res.end();
        }
        if(USERS[i].email === req.body.email && bcrypt.compare(req.body.password, USERS[i].password)) {
            target = USERS[i];
        }
    }
    if(target === undefined) {
       res.status(404).send("cannot find user")
       res.end();
    }
    else {
        const token = jwt.sign(target, 'Rc123456!', {expiresIn: '10h'});
        const rToken = (REFRESHTOKENS.length).toString();
        REFRESHTOKENS.push(rToken);
        res.status(200).json({accessToken: token, refreshToken: rToken , email: target.email, name: target.name, isAdmin: target.isAdmin})
        res.end();
    }
})

app.post("/users/tokenValidate", (req, res, next)=>{
    const token = req.header('Authorization').split(" ")[1];
    if(token === undefined) {
        res.status(401).send("Access Token Required")
    }
    if(!jwt.verify(token, 'Rc123456!')) {
        res.status(403).send("Invalid Access Token");
        res.end();
    }
    else {
        res.status(200).json({valid: true});
        res.end();
    }
})

app.get("/api/v1/information", (req, res, next)=>{
    const token = req.header('Authorization').split(" ")[1];
    let target;
    if(token === undefined) {
        res.status(401).send("Access Token Required")
    }
    else {
        try{
        jwt.verify(token, 'Rc123456!');
        }
        catch {
            res.status(403).send("Invalid Access Token");
        res.end();
        }
        const user = jwt.verify(token, 'Rc123456!');
        for(let i = 0; i < INFORMATION.length; i++){
            if(user.email === INFORMATION[i].email){
                res.status(200).send(body = [{email: INFORMATION[i].email},{info: INFORMATION[i].info}]);
                res.end();
                return;
            }
        }
    }
})

app.post("/users/token", (req, res, next)=>{
    const token = req.body.token;
    if(token === undefined) {
        res.status(401).send("Refresh Token Required")
    }
    if(!REFRESHTOKENS.includes(token)) {
        res.status(403).send("Invalid Refresh Token");
        res.end();
    }
    else {
        const user = jwt.verify(token, 'Rc123456!')
        const newToken = jwt.sign(user, 'Rc123456!', {expiresIn: '10s'})
        REFRESHTOKENS.splice(REFRESHTOKENS.indexOf(token), 1);
        REFRESHTOKENS.push(newToken);
        res.status(200).send(newToken)
    }
})

app.post("/users/logout", (req, res, next)=>{
    const token = req.body.token;
    if(token === undefined) {
        res.status(400).send("Refresh Token Required")
    }
    if(!REFRESHTOKENS.includes(token)) {
        res.status(400).send("Invalid Refresh Token");
        res.end();
    }
    else {
        REFRESHTOKENS.splice(REFRESHTOKENS.indexOf(token), 1);
        res.status(200).send("User Logged Out Successfully")
    }
})

app.get('/api/v1/users', (req, res, next)=>{
    const token = req.headers.Authorization.split(" ")[1];
    if(token === undefined) {
        res.status(401).send("Access Token Required")
    }
    if(!REFRESHTOKENS.includes(token)) {
        res.status(403).send("Invalid Access Token");
        res.end();
    }
    else {
        const user = jwt.verify(token, 'Rc123456!')
        if(user.isAdmin === false) {
            res.end();
            return;
        }
        else {
            res.status(200).send({USERS: USERS})
        }
    }
})

app.options('/', (req, res, next)=>{
    const token = req.headers.Authorization.split(" ")[1];
    if(token === undefined) {
        res.status(200).setHeader('allow', '"OPTIONS, GET, POST"').send([{ method: "post", path: "/users/register", description: "Register, Required: email, name, password", example: { body: { email: "user@email.com", name: "user", password: "password" } } },
        { method: "post", path: "/users/login", description: "Login, Required: valid email and password", example: { body: { email: "user@email.com", password: "password" } } }])
        res.end();
    }
    else if(!REFRESHTOKENS.includes(token)) {
        res.status(200).setHeader('allow', '"OPTIONS, GET, POST"').send([{ method: "post", path: "/users/register", description: "Register, Required: email, name, password", example: { body: { email: "user@email.com", name: "user", password: "password" } } },
        { method: "post", path: "/users/login", description: "Login, Required: valid email and password", example: { body: { email: "user@email.com", password: "password" } } },
        { method: "post", path: "/users/token", description: "Renew access token, Required: valid refresh token", example: { headers: { token: "\*Refresh Token\*" } } }])
    }
    else {
        const user = jwt.verify(token, 'Rc123456');
        if(user.isAdmin === false) {
            res.status(200).setHeader('allow', '"OPTIONS, GET, POST"').send([{ method: "post", path: "/users/register", description: "Register, Required: email, name, password", example: { body: { email: "user@email.com", name: "user", password: "password" } } },
            { method: "post", path: "/users/login", description: "Login, Required: valid email and password", example: { body: { email: "user@email.com", password: "password" } } },
            { method: "post", path: "/users/token", description: "Renew access token, Required: valid refresh token", example: { headers: { token: "\*Refresh Token\*" } } },
            { method: "post", path: "/users/tokenValidate", description: "Access Token Validation, Required: valid access token", example: { headers: { Authorization: "Bearer \*Access Token\*" } } },
            { method: "get", path: "/api/v1/information", description: "Access user's information, Required: valid access token", example: { headers: { Authorization: "Bearer \*Access Token\*" } } },
            { method: "post", path: "/users/logout", description: "Logout, Required: access token", example: { body: { token: "\*Refresh Token\*" } } }])
        }
        else {
            res.status(200).setHeader('allow', '"OPTIONS, GET, POST"').send([
                { method: "post", path: "/users/register", description: "Register, Required: email, name, password", example: { body: { email: "user@email.com", name: "user", password: "password" } } },
                { method: "post", path: "/users/login", description: "Login, Required: valid email and password", example: { body: { email: "user@email.com", password: "password" } } },
                { method: "post", path: "/users/token", description: "Renew access token, Required: valid refresh token", example: { headers: { token: "\*Refresh Token\*" } } },
                { method: "post", path: "/users/tokenValidate", description: "Access Token Validation, Required: valid access token", example: { headers: { Authorization: "Bearer \*Access Token\*" } } },
                { method: "get", path: "/api/v1/information", description: "Access user's information, Required: valid access token", example: { headers: { Authorization: "Bearer \*Access Token\*" } } },
                { method: "post", path: "/users/logout", description: "Logout, Required: access token", example: { body: { token: "\*Refresh Token\*" } } },
                { method: "get", path: "api/v1/users", description: "Get users DB, Required: Valid access token of admin user", example: { headers: { authorization: "Bearer \*Access Token\*" } } }
              ])
        }
    }
})

module.exports = app;