const express = require('express')
const mysql = require('mysql2/promise')
const bodyParser = require('body-parser')
const cors = require('cors')
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');
const cookie = require('cookie')

const PORT = 8000

let conn = null

const initMySQL = async () => {
    conn = await mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: 'root',
        database: 'tutorials',
        port: 3306
    })
}

const verifyToken = (req, res, next) => {
    const token = req.header('Authorization')
    // const token = c.jwt

    if (!token) return res.status(401).json({ error: 'Access denied' })
    try {
        const decoded = jwt.verify(token, 'your-secret-key');
        req.userId = decoded.userId;
        // console.log("decode : ", decoded.userId);
        // console.log("req", req.userId);
        // console.log(userId);
        next()
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
}

const app = express()
app.use(bodyParser.json())
app.use(cors())

app.use('/books', verifyToken)

// book api

app.get('/books', async (req, res) => {
    try {
        let result = await conn.query("SELECT * FROM books")
        res.status(200).json(result[0])
    } catch (error) {
        console.log('Error : ', error.message);
        res.status(500).json({ message: 'someting went wrong' })
    }
})

app.get('/books/:id', async (req, res) => {
    try {
        let id = req.params.id
        let result = await conn.query("SELECT * FROM books WHERE id = ?", [id])

        if (result[0].length == 0) {
            throw { statusCode: 404, message: "user not found" }
        }

        res.status(200).json(result[0][0])
    } catch (error) {
        console.log('Error : ', error.message);
        let statusCode = error.statusCode || 500
        res.status(statusCode).json({ message: 'someting went wrong' })
    }
})

app.post('/books', async (req, res) => {
    try {
        let book = req.body
        let result = await conn.query("INSERT INTO books SET ?", [book])
        res.status(200).json({
            message: 'create book successful',
            result: result
        })
    } catch (error) {
        console.log('Error : ', error.message);
        res.status(500).json({ message: 'someting went wrong' })
    }
})

app.put('/books/:id', async (req, res) => {
    try {
        let id = req.params.id
        let book = req.body
        let result = await conn.query("UPDATE books SET ? WHERE id = ?", [book, id])
        res.status(200).json({
            message: 'update book successful',
            result: result
        })
    } catch (error) {
        console.log('Error : ', error.message);
        res.status(500).json({ message: 'someting went wrong' })
    }
})

app.delete('/books/:id', async (req, res) => {
    try {
        let id = req.params.id
        await conn.query("DELETE FROM books WHERE id = ?", id)
        res.status(200).json({
            message: 'delete book successful',
        })
    } catch (error) {
        console.log('Error : ', error.message);
        res.status(500).json({ message: 'someting went wrong' })
    }
})

// user api

app.post('/register', async (req, res) => {
    try {
        let user = req.body

        let checkUser = await conn.query('SELECT * FROM users WHERE username = ?', user.username)
        if (checkUser[0][0]) {
            throw new Error('This user already exists');
        }
        // เข้ารหัสด้วย bcrypt
        await bcrypt.genSalt(saltRounds, function (err, salt) {
            bcrypt.hash(user.password, salt, function (err, hash) {
                // Store hash in your password DB.
                if (err != null) {
                    res.json({
                        message: "someting went wrong"
                    })
                }
                newUser = {
                    username: user.username,
                    password: hash
                }
                conn.query('INSERT INTO users SET ?', [newUser])
                res.status(200).json({
                    message: 'register user successful',
                })
            });
        });
    } catch (error) {
        console.log('Error : ', error.message);
        res.status(500).json({ message: 'someting went wrong' })
    }
})

app.post('/login', async (req, res) => {
    try {
        let user = req.body
        let checkUser = await conn.query('SELECT * FROM users WHERE username = ?', user.username)

        const selectUser = checkUser[0][0]


        await bcrypt.compare(user.password, selectUser.password, function (err, result) {
            if (err) {
                // Handle error
                console.error('Error comparing passwords:', err);
                return;
            }

            if (result) {
                // Passwords match, authentication successful
                console.log('Passwords match! User authenticated.');
                const token = jwt.sign({ userId: selectUser.id }, 'your-secret-key', {
                    expiresIn: '1h',
                });
                res.setHeader(
                    "Set-Cookie",
                    cookie.serialize("jwt", String(token), {
                        httpOnly: true,
                        maxAge: 60 * 60 * 24 * 7, // 1 week
                    }),
                );
                res.status(200).json({ token });
            } else {
                // Passwords don't match, authentication failed
                console.log('Passwords do not match! Authentication failed.');
            }
        });

    } catch (error) {
        console.log('Error : ', error.message);
        res.status(500).json({ message: 'someting went wrong' })
    }
})

app.get('/user', verifyToken, async (req, res) => {
    try {
        let result = await conn.query("SELECT * FROM users WHERE id = ?", req.userId)
        res.status(200).json(result[0][0])
    } catch (error) {
        console.log('Error : ', error.message);
        res.status(500).json({ message: 'someting went wrong' })
    }
})


app.listen(PORT, async (req, res) => {
    await initMySQL()
    console.log(`server starting now port:${PORT}`);
})

