import User from "../models/User.js"
import Session from "../models/Session.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const ACCESS_TOKEN_TTL = "30m"; 
const REFRESH_TOKEN_TTL = 14 * 24 * 60 * 60 * 1000; // 14 days in milliseconds

export const signUp = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // validate 
    if(!username || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // check user exists
    const existingUser = await User.findOne({ email });
    if(existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // create user
    const user = await User.create({ username, email, hashedPassword });

    return res.status(201).json({ message: "User created successfully" });
  } catch(error) {
    console.log('signUp error__:', error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export const signIn = async (req, res) => {
  try {
    const { username, password } = req.body;

    // validate
    if(!username || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    // check user exists
    const user = await User.findOne({ username });
    if(!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // compare password
    const isPasswordValid = await bcrypt.compare(password, user.hashedPassword);
    if(!isPasswordValid) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    
    // generate token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: ACCESS_TOKEN_TTL });

    // generate refresh token
    const refreshToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: REFRESH_TOKEN_TTL });

    // save session
    await Session.create({ userId: user._id, refreshToken, expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL) });

    res.cookie("refreshToken", refreshToken, { 
      httpOnly: true, 
      secure: process.env.NODE_ENV === "production", 
      sameSite: "none",
      maxAge: REFRESH_TOKEN_TTL 
    });

    return res.status(200).json({ message: "Login successful", token });
  } catch(error) {
    console.log('signIn error__:', error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export const signOut = async (req, res) => {
  try {
    const { refreshToken } = req.cookies;

    if(!refreshToken) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // find session
    const session = await Session.findOne({ refreshToken });
    if(!session) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // delete session
    await Session.deleteOne({ _id: session._id });

    return res.status(200).json({ message: "Logout successful" });
  } catch(e) {
    console.log('signOut error__:', error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export const refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.cookies;
    if(!refreshToken) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // find session
    const session = await Session.findOne({ refreshToken });
    if(!session) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // check if token is expired
    if(session.expiresAt < Date.now()) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // generate new access token
    const newAccessToken = jwt.sign({ userId: session.userId }, process.env.JWT_SECRET, { expiresIn: ACCESS_TOKEN_TTL });

    return res.status(200).json({ message: "Token refreshed", token: newAccessToken });
  } catch(e) {
    console.log('refreshToken error__:', error);
    return res.status(500).json({ message: "Internal server error" });
  }
}