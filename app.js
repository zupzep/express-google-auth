import express from "express";
import cors from "cors";
import { OAuth2Client } from "google-auth-library";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

app.use(
  cors({
    origin: "http://localhost:4000",
    credentials: true,
  })
);
app.use(express.json());

app.get("/", async (req, res) => {
  res.send('test');
});

app.post("/auth/google", async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ 
      message: "Token required" 
    });

    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();

    if (!payload) return res.status(401).json({ message: "Invalid token" });

    const token = jwt.sign(
      { 
        sub: payload.sub, 
        email: payload.email, 
        name: payload.name 
      },
      process.env.JWT_SECRET,
      { 
        expiresIn: "1h" 
      }
    );

    res.json({ 
      user: payload, 
      token
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ 
      message: "Server error" 
    });
  }
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));

