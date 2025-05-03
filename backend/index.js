const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const pg = require('pg');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
require('dotenv').config();


const app = express();
const port = 3000;

// 📦 PostgreSQL connectie
const pool = new pg.Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    connectionTimeoutMillis: 5000
});

// 🌐 Alleen frontend op localhost:8080 mag toegang
const allowedOrigins = ['http://localhost:8080'];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Niet toegelaten door CORS'));
        }
    }
}));

// 🧠 JSON en form body parsing
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ✅ Registratie endpoint (maakt nieuwe gebruiker aan met gehashte password)
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!validator.isAlphanumeric(username)) {
        return res.status(400).send('Gebruikersnaam mag alleen letters en cijfers zijn');
    }
    if (!validator.isLength(password, { min: 8 })) {
        return res.status(400).send('Wachtwoord moet 8 kerakters minimaal zijn');
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query = `INSERT INTO users (user_name, password) VALUES ($1, $2) RETURNING id`;
        const values = [username, hashedPassword];
        const result = await pool.query(query, values);
        res.status(201).json({ userId: result.rows[0].id });
    } catch (err) {
        console.error(err);
        res.status(500).send('Registratie mislukt');
    }
});
const loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 10,
    message: 'te veel keer het wachtwoord verkeerd ingegeven, probeer later het opnieuw '
});


// 🔐 Login endpoint (verifieert username + password)
app.post('/authenticate', loginLimiter,async (req, res) => {
    const { username, password } = req.body;
    if (!validator.isAlphanumeric(username)) {
        return res.status(400).send('Ongeldige gebruikersnaam');
    }
    if (!validator.isLength(password, { min: 8 })) {
        return res.status(400).send('Wachtwoord moet 8 kerakters minimaal zijn');
    }
    try {
        const query = `SELECT * FROM users WHERE user_name = $1`;
        const values = [username];
        const result = await pool.query(query, values);

        if (result.rows.length === 0) {
            return res.status(401).send('Gebruiker niet gevonden');
        }

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).send('Ongeldig wachtwoord');
        }

        res.status(200).json({ message: 'Succesvol ingelogd', user: { id: user.id, username: user.user_name } });
    } catch (err) {
        console.error(err);
        res.status(500).send('Authenticatie mislukt');
    }
});

app.listen(port, () => {
    console.log(`App running on port ${port}.`);
});