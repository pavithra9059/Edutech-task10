require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const User = require("./models/User");
const authMiddleware = require("./middleware/authMiddleware");

const app = express();

app.use(express.json());
app.use(cors());


// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
.then(() => console.log("MongoDB Connected"))
.catch(err => console.log(err));


// ================= REGISTER =================

app.post("/register", async (req, res) => {

    try {

        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                message: "All fields are required"
            });
        }

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).json({
                message: "User already exists"
            });
        }

        const hashedPassword =
            await bcrypt.hash(password, 10);

        const user = await User.create({
            name,
            email,
            password: hashedPassword
        });

        res.status(201).json({
            success: true,
            message: "User registered successfully",
            userId: user._id
        });

    } catch (error) {

        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});


// ================= LOGIN =================

app.post("/login", async (req, res) => {

    try {

        const { email, password } = req.body;

        const user =
            await User.findOne({ email });

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        const isMatch =
            await bcrypt.compare(
                password,
                user.password
            );

        if (!isMatch) {
            return res.status(401).json({
                message: "Invalid credentials"
            });
        }

        const token = jwt.sign(
            {
                id: user._id,
                email: user.email
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "1h"
            }
        );

        res.status(200).json({
            success: true,
            message: "Login successful",
            token
        });

    } catch (error) {

        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});


// ================= PROTECTED ROUTE =================

app.get(
    "/profile",
    authMiddleware,
    async (req, res) => {

        try {

            const user =
                await User.findById(req.user.id)
                .select("-password");

            res.status(200).json(user);

        } catch (error) {

            res.status(500).json({
                message: error.message
            });
        }
    }
);


// ================= HOME =================

app.get("/", (req, res) => {
    res.send("JWT Authentication API Running");
});


// ================= START SERVER =================

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(
        `Server running on port ${PORT}`
    );
});
