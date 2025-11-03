import express from "express";
import dotenv from "dotenv";
import authRoute from "./routes/authRoute.js";
import cookieParser from "cookie-parser";
import { connectDB } from "./libs/db.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5001;

// middlewares
app.use(express.json());
app.use(cookieParser());

// public routes
app.use("/api/auth", authRoute);

// private routes

// connect DB and run app 
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
  });
}).catch((err) => {
  console.log(err);
  process.exit(1)
});
