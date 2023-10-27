var express = require('express')
var cors = require('cors')
var app = express()
var bodyParser = require('body-parser')
var jsonParser = bodyParser.json()
const bcrypt = require('bcrypt');
const saltRounds = 10;  // เป็น rounds ที่ใช้ในการ generate pass.
var jwt = require('jsonwebtoken');
const secret = 'Fullstack-Login-2023' // ใช้ในการ generate token

app.use(cors())

const mysql = require('mysql2');
// create the connection to database
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    database: 'mydb'
  });

app.post('/register', jsonParser, function (req, res, next) { 
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) { //เราจะทำการ hash password ก่อนที่จะ save ลงทานข้อมูล
    // Store hash in your password DB.

    // execute will internally call prepare and query
    connection.execute(
        'INSERT INTO users (email, password, fname, lname) VALUES (?, ?, ?, ?)',
        [req.body.email, hash, req.body.fname, req.body.lname],
        function(err, results, fields) {
            if (err) {
                res.json({status: 'error', message: err})
                return
            }
          res.json({status: 'ok'})
          // If you execute same statement again, it will be picked from a LRU cache
          // which will save query preparation time and give better performance
        }
      );  
    });
})
// สร้าง login
// โดยใช้ jason token ในการยืนยันตัวตน
app.post('/login', jsonParser, function (req, res, next) { 
    connection.execute(
        'SELECT * FROM users WHERE email=?',
        [req.body.email],
        function(err, users, fields) {
            if (err) {
                res.json({status: 'error', message: err});
                return
            }
            if (users.length == 0) { res.json({status: 'eror', message: 'no user fond'}); return }

            // Load hash from your password DB.
            bcrypt.compare(req.body.password, users[0].password, function(err, isLogin) {  //compare ใช้ตรวจสอบ Password ที่ไม่ได้เข้ารหัสกับในฐานข้อมูลตรงกันรึป่าว
                if (isLogin) {
                    var token = jwt.sign({ email: users[0].email }, secret, { expiresIn: '1h' });
                    res.json({status: 'ok', message:'login success', token})
                } else {
                    res.json({status: 'error', message: 'login failed'})
                }
            });
          // If you execute same statement again, it will be picked from a LRU cache
          // which will save query preparation time and give better performance
        }
    );
})

app.post('/authen', jsonParser, function (req, res, next){
    try {
        const token = req.headers.authorization.split(' ')[1]
        var decoded = jwt.verify(token, secret);
        res.json({status: 'ok', decoded})
    } catch(err) {
        res.json({status: 'error', message: err.message})
    }
})

app.listen(3333, function () { ถึงนาทีที่ 36.56
  console.log('CORS-enabled web server listening on port 3333')
})
// ขั้นที่ 2 จะเพิ่มลอจิกในเส้น API ของ '/register'