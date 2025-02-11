const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

const PORT = 5000;
const JWT_SECRET ="supersecretkey";
const ADMIN_API_KEY ="secureapikey";


const db = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "pass123",
    database: "workindia",
});


const authenticateUser = async (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ error: "Access denied" });

    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ error: "Invalid Token" });
    }
};


const authenticateAdmin = (req, res, next) => {
    const apiKey = req.headers["x-api-key"];
    console.log(req.headers);
    console.log(apiKey);
    if (!apiKey || apiKey !== ADMIN_API_KEY) {
        return res.status(403).json({ error: "Forbidden: Invalid API Key" });
    }
    next();
};


app.post("/register", async (req, res) => {
    try {
        const { name, email, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await db.execute(
            "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)",
            [name, email, hashedPassword, role || "user"]
        );

        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const [users] = await db.execute("SELECT * FROM users WHERE email = ?", [email]);

        if (users.length === 0) return res.status(404).json({ error: "User not found" });

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: "10h" });

        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.post("/addtrains", authenticateAdmin, async (req, res) => {
    try {
        const { train_name, source, destination, total_seats } = req.body;
        await db.execute(
            "INSERT INTO trains (train_name, source, destination, total_seats, available_seats) VALUES (?, ?, ?, ?, ?)",
            [train_name, source, destination, total_seats, total_seats]
        );

        res.status(201).json({ message: "Train added successfully" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.post("/available_seat_trains", async (req, res) => {
    try {
        const { source, destination } = req.body;
        const [trains] = await db.execute(
            "SELECT * FROM trains WHERE source = ? AND destination = ?",
            [source, destination]
        );

        res.json(trains);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.post("/book", authenticateUser, async (req, res) => {
    const { train_id } = req.body;
    const user_id = req.user.id;

    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();

        
        const [train] = await connection.execute(
            "SELECT available_seats FROM trains WHERE id = ? FOR UPDATE",
            [train_id]
        );

        if (train.length === 0 || train[0].available_seats <= 0) {
            throw new Error("No seats available");
        }

    
        await connection.execute(
            "UPDATE trains SET available_seats = available_seats - 1 WHERE id = ?",
            [train_id]
        );

        
        await connection.execute(
            "INSERT INTO bookings (user_id, train_id) VALUES (?, ?)",
            [user_id, train_id]
        );

        await connection.commit();
        res.status(201).json({ message: "Seat booked successfully" });
    } catch (error) {
        await connection.rollback();
        res.status(500).json({ error: error.message });
    } finally {
        connection.release();
    }
});


app.get("/bookings", authenticateUser, async (req, res) => {
    try {
        const user_id = req.user.id;
        const [bookings] = await db.execute(
            "SELECT trains.train_name, trains.source, trains.destination FROM bookings INNER JOIN trains ON bookings.train_id = trains.id WHERE bookings.user_id = ?",
            [user_id]
        );

        res.json(bookings);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
