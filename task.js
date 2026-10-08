require("dotenv").config();
const bcrypt = require("bcrypt");
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// 1. User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    role: { type: String, enum: ["user", "admin"], default: "user" }
});

// 2. Password hashing with bcrypt
userSchema.pre("save", async function () {
    // Only hash if the password is new or has been modified
    if (!this.isModified("password")) return;
    this.password = await bcrypt.hash(this.password, 10);
});

const User = mongoose.model("User", userSchema);

// 3. User Registration
app.post("/users", async (req, res) => {
    try {
        const newUser = req.body;
        const result = await User.create(newUser);

        // Do not return the password
        const userResponse = result.toObject();
        delete userResponse.password;

        res.status(201).json({
            message: "User added successfully",
            user: userResponse
        });
    } catch (error) {
        res.status(400).json({
            message: error.message
        });
    }
});

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email }).select("+password");
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid credentials" });
        }

        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({
            message: "Login successful",
            token,
            role: user.role          // so the client knows if it's admin or user
        });
    } catch (error) {
        res.status(500).json({ message: "Failed to login" });
    }
});

async function connectDB() {
    try {
        await mongoose.connect("mongodb://localhost:27017/userDB");
        console.log("MongoDB connected");

        app.listen(3000, () => {
            console.log("Server running on port 3000");
        });
    } catch (error) {
        console.log("MongoDB connection failed");
        console.log(error);
    }
}

connectDB();