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
    origin: "https://next-google-auth-bice.vercel.app",
    credentials: true,
  })
);
app.use(express.json());

app.get("/", async (req, res) => {
  res.send("test");
});

// Step 1: Redirect user to Google login
app.get("/auth/google", (req, res) => {
  const url = client.generateAuthUrl({
    access_type: "offline", // untuk refresh token
    scope: ["profile", "email"],
    redirect_uri: "https://express-google-auth.vercel.app/auth/google/callback",
    prompt: "consent",
  });
  res.redirect(url);
});

// Step 2: Google callback
app.get("/auth/google/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("Missing code");

  try {
    // Tukar code dengan token Google
    const { tokens } = await client.getToken({
      code,
      redirect_uri: "https://express-google-auth.vercel.app/auth/google/callback",
    });
    client.setCredentials(tokens);

    // Verifikasi ID token
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token!,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();

    if (!payload) return res.status(401).send("Invalid token");

    // Buat JWT sendiri
    const jwtToken = jwt.sign(
      {
        sub: payload.sub,
        email: payload.email,
        name: payload.name,
        picture: payload.picture,
      },
      process.env.JWT_SECRET!,
      { expiresIn: "1h" }
    );

    // Redirect ke FE dengan token
    res.redirect(
      `https://next-google-auth-bice.vercel.app`
    );
  } catch (err) {
    console.error(err);
    res.status(500).send("Google Auth failed");
  }
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));

