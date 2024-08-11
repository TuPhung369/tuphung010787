import session from "express-session"; // Import express-session for session management
import connectRedis from "connect-redis"; //  Import connect-redis for session storage
import Redis from "ioredis"; // Import ioredis for Redis client
import express from "express"; // Import express for building REST APIs

import dotenv from "dotenv"; // Import dotenv for loading environment variables
import path from "path"; // Import path for working with file and directory paths
import { fileURLToPath } from "url"; // Import fileURLToPath for converting file URLs to file paths
import { dirname } from "path"; //  Import dirname for getting the directory name of a path
import router1 from "./apiRouter.js";
import accountRouter from "./routers/account.js";
import AccountModel from "./models/account.js";
import jwt from "jsonwebtoken"; // Import jsonwebtoken for generating JWT tokens
import cookieParser from "cookie-parser"; // Import cookie-parser for parsing cookies
import passport from "passport"; // Import passport for authentication Strategies
import LocalStrategy from "passport-local"; // 2FA by username and password
import RedisStore from "connect-redis"; // Import RedisStore for session storage
import bcrypt from "bcrypt"; // Import bcrypt for password hashing
import FacebookStrategy from "passport-facebook"; // 2FA by Facebook authentication
import OAuth2Strategy from "passport-google-oauth20"; // 2FA by Google authentication
import GitHubStrategy from "passport-github2"; // 2FA by github authentication
import speakeasy from "speakeasy"; //2FA by Microsoft or Google authentication
import QRCode from "qrcode"; // 2FA by Microsoft or Google authentication
import twilio from "twilio"; // 2FA by SMS and Calling - recover code - 'WFP66YGZ6BGBLPPGXZM8M8P4'
import admin from "./firebaseConfig.js"; // Import Firebase Admin SDK
import cors from "cors"; // Import cors for enabling Cross-Origin Resource Sharing (CORS)
import nodemailer from "nodemailer"; // Import nodemailer for sending emails

dotenv.config(); // Load environment variables

const app = express();
const port = process.env.PORT || 3000; // Default to port 3000 if PORT is not defined
const JWT_PASSPHRASE = process.env.JWT_PASSPHRASE;
const redisClient = new Redis({
  host: process.env.REDIS_HOST || "localhost",
  port: process.env.REDIS_PORT || 6379,
  password: process.env.REDIS_PASSWORD,
  maxRetriesPerRequest: 5, // Increase max retries
  connectTimeout: 10000, // Increase connection timeout
});

// Error handling for Redis connection
redisClient.on("error", (err) => {
  console.error("Redis connection error:", err);
});
redisClient.on("ready", () => {
  console.log("Redis client connected successfully");
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);
// CORS middleware
const allowCrossDomain = (req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE");
  res.header("Access-Control-Allow-Headers", "Content-Type");
  next();
};

// Store OTPs
let otpStore = {};

// Email setup (using Nodemailer with Gmail for this example)
let transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

// Use middleware to parse JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(cookieParser());
app.set("trust proxy", 1); // Trust first proxy

// Session setup
app.use(
  session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: false, // Set to true if your site is served over HTTPS
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24, // Session max age in milliseconds (10 minutes)
    },
  })
);

// Passport.js setup
app.use(passport.initialize());
app.use(passport.session());

// Local Strategy
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await AccountModel.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username." });
      }

      // Compare the provided password with the stored hashed password
      const isMatch = await bcrypt.compare(password, user.password);
      // console.log("isMatch:", isMatch);

      if (!isMatch) {
        return done(null, false, { message: "Incorrect password." });
      }

      // If passwords match, return the user object (user now authenticated)
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

// STEP 6: Facebook Strategy
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/facebook/callback",
      profileFields: ["id", "displayName", "photos", "email"],
    },
    async function (accessToken, refreshToken, profile, done) {
      try {
        const existingAccount = await AccountModel.findOne({
          otherId: profile.id,
        });

        if (existingAccount) {
          return done(null, existingAccount);
        } else {
          // Create new user if not found
          const newAccount = new AccountModel({
            username: profile.displayName,
            password: profile.id,
            role: "user",
            otherId: profile.id,
            accessToken: accessToken,
            photos: profile.photos
              ? profile.photos.map((photo) => photo.value)
              : [], // Ensure photos is an array of strings
            email:
              profile.emails && profile.emails[0]
                ? profile.emails[0].value
                : null, // Ensure email exists
            phone: profile.phoneNumbers && profile.phoneNumbers[0]
                ? profile.phoneNumbers[0].value
                : "+8477366686",
          });

          await newAccount.save();
          return done(null, newAccount);
        }
      } catch (err) {
        return done(err);
      }
    }
  )
);
// STEP 6: Google Strategy
// Configure Google OAuth 2.0 strategy
//authorizationURL: "https://accounts.google.com/o/oauth2/auth",
//tokenURL: "https://oauth2.googleapis.com/token",
passport.use(
  new OAuth2Strategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/callback",
      scope: ["email"],
    },
    async function (accessToken, refreshToken, profile, done) {
      try {
        //console.log("Profile:", profile);
        const existingAccount = await AccountModel.findOne({
          otherId: profile.id,
        });

        if (existingAccount) {
          // If account exists, just return it
          return done(null, existingAccount);
        } else {
          // Create new user if not found
          const username =
            profile.displayName ||
            (profile.emails && profile.emails[0] && profile.emails[0].value);

          // Check if username already exists
          const existingAccount = await AccountModel.findOne({
            username: username,
          });
          if (existingAccount) {
            return done(null, existingAccount);
          } else {
            const newAccount = new AccountModel({
              username: username,
              password: profile.id,
              role: "user",
              otherId: profile.id,
              accessToken: accessToken,
              photos: profile.photos
                ? profile.photos.map((photo) => photo.value)
                : [],
              email:
                profile.emails && profile.emails[0]
                  ? profile.emails[0].value
                  : null,
              phone: profile.phoneNumbers && profile.phoneNumbers[0]
                ? profile.phoneNumbers[0].value
                : "+84773666869",
            });

            await newAccount.save();
            return done(null, newAccount);
          }
        }
      } catch (err) {
        return done(err);
      }
    }
  )
);
// STEP 6: GitHub Strategy
passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/github/callback",
    },
    async function (accessToken, refreshToken, profile, done) {
      try {
        const existingAccount = await AccountModel.findOne({
          otherId: profile.id,
        });

        if (existingAccount) {
          // If account exists, just return it
          return done(null, existingAccount);
        } else {
          // Create new user if not found
          const username = profile.username || profile.displayName;

          // Check if username already exists
          const existingAccount = await AccountModel.findOne({
            username: username,
          });
          if (existingAccount) {
            return done(null, existingAccount);
          } else {
            const newAccount = new AccountModel({
              username: username,
              password: profile.id,
              role: "user",
              otherId: profile.id,
              accessToken: accessToken,
              photos: profile.photos
                ? profile.photos.map((photo) => photo.value)
                : [],
              email:
                profile.emails && profile.emails[0]
                  ? profile.emails[0].value
                  : null,
              phone: profile.phoneNumbers && profile.phoneNumbers[0]
                  ? profile.phoneNumbers[0].value
                  : "+84773666866",
            });

            await newAccount.save();
            return done(null, newAccount);
          }
        }
      } catch (err) {
        return done(err);
      }
    }
  )
);

// Passport.js uses serializeUser and deserializeUser methods to manage user sessions. These methods are essential for storing user data in the session and retrieving it when needed.
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await AccountModel.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

const fireStore = admin.firestore();
app.use(allowCrossDomain);
app.use(express.static(path.join(__dirname, "public")));
const checkLogin = async (req, res, next) => {
  try {
    const token = req.cookies.token;
    const idUser = jwt.verify(token, JWT_PASSPHRASE);
    const data = await AccountModel.findOne({ _id: idUser._id });
    if (!data) {
      throw new Error("Account not found");
    }
    req.data = data;
    next();
  } catch (error) {
    res.status(401).json("Unauthorized or Token not found");
  }
};

const checkTeacher = (req, res, next) => {
  if (req.data.role === "manager" || req.data.role === "teacher") {
    next();
  } else {
    res.status(403).json("Forbidden");
  }
};

const checkManager = (req, res, next) => {
  if (req.data.role === "manager") {
    next();
  } else {
    res.status(403).json("Forbidden");
  }
};
const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    //console.log("Authenticated:", req.user);
    return next(); // User is authenticated, proceed to the next middleware
  }
  res.redirect("/login"); // Redirect to login if not authenticated
};
// Register
app.get("/register", (req, res, next) => {
  const pathRegister = path.join(__dirname, "register.html");
  res.sendFile(pathRegister);
});
app.post("/register", async (req, res) => {
  const { username, password, role } = req.body;

  try {
    // Check if the username already exists
    const existingAccount = await AccountModel.findOne({ username });

    if (existingAccount) {
      return res.status(400).json("Account already exists");
    }

    // Hash the password using bcrypt
    const hashedPassword = await bcrypt.hash(password, 10); // Increase the work factor if needed

    // Create new account document
    const newAccount = new AccountModel({
      username,
      password: hashedPassword,
      role,
    });

    // Save the new account to the database
    await newAccount.save();

    res.status(201).json("Account created successfully");
  } catch (err) {
    console.error("Error registering account:", err);
    res.status(500).json("Error registering account");
  }
});

// Login
app.get("/login", (req, res, next) => {
  const pathLogin = path.join(__dirname, "login.html");
  res.sendFile(pathLogin);
});

// Login route with OTP and SMS verification
app.post("/login", async (req, res, next) => {
  passport.authenticate("local", async (err, user, info) => {
    if (err) {
      console.error("Authentication error:", err);
      return next(err);
    }
    if (!user) {
      console.warn("User not found or password incorrect:", info.message);
      return res.status(401).json({ message: info.message });
    }

    const { otp, smsCode } = req.body;
    console.log("User authenticated, starting OTP/SMS verification...");

    try {
      const userFromDb = await AccountModel.findOne({ username: user.username });
      const userOtpSecret = userFromDb.otpSecret;

      let otpVerified = false;
      if (userOtpSecret) {
        otpVerified = speakeasy.totp.verify({
          secret: userOtpSecret,
          encoding: "base32",
          token: otp,
          window: 10,
        });
        console.log(`OTP verified: ${otpVerified}`);
      }

      let smsVerified = false;
      if (smsCode) {
        smsVerified = await verifySMS(userFromDb.phone, smsCode);
        console.log(`SMS verified: ${smsVerified}`);
      }

      if ((userOtpSecret && !otpVerified) || (smsCode && !smsVerified)) {
        console.warn("Invalid OTP or SMS code");
        return res.status(401).json({ error: "Invalid OTP or SMS code" });
      }

      req.logIn(user, (err) => {
        if (err) {
          console.error("Login error:", err);
          return next(err);
        }

        const token = jwt.sign({ _id: user._id }, process.env.JWT_PASSPHRASE);
        res.cookie("token", token, { httpOnly: true });
        res.json({ message: "Login successful", token });
      });
    } catch (err) {
      console.error("Error during OTP/SMS verification:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
  })(req, res, next);
});

app.get("/users/:username", (req, res, next) => {
  // Implement your logic to fetch user data here
  res.send(`Welcome ${req.params.username}`);
});
// Facebook Initiate authentication with 
app.get(
  "/auth/facebook",
  passport.authenticate("facebook", { scope: ["email"] })
);
// Facebook callback handler
app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    // Generate JWT token after successful Facebook authentication
    const token = jwt.sign(
      {
        userId: req.user._id,
        accessToken: req.user.accessToken,
        role: req.user.role,
        username: req.user.username,
        otherId: req.user.otherId,
      },
      process.env.JWT_PASSPHRASE,
      {
        expiresIn: "24h", // Adjust expiration as needed
      }
    );

    // Set the token in a cookie (assuming you want to store it this way)
    res.cookie("token", token, {
      httpOnly: true,
      // secure: true, // Uncomment for HTTPS environments
      maxAge: 24 * 60 * 60 * 1000, // Example: 24 hours expiration
      path: "/", // Ensure cookie is accessible across the entire site
    });

    // Redirect to a protected route or respond with JSON data
    res.redirect("/facebook");
  }
);
app.get("/facebook", ensureAuthenticated, async (req, res) => {
  const token = req.cookies.token; // Assuming token is stored in a cookie

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_PASSPHRASE);

    // Fetch user details based on decoded payload
    const userId = decoded.userId;
    const user = await AccountModel.findById(userId);

    if (!user) {
      throw new Error("User not found");
    }

    res.json({ message: `Welcome ${user.username}`, user: req.user });
  } catch (error) {
    console.error("Token verification failed:", error.message);
    res.status(401).json({ message: "Unauthorized" });
  }
});

// Google Initiate authentication with 
app.get("/auth/google", passport.authenticate("google", { scope: ["email"] }));

// Google OAuth callback
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Generate JWT token after successful Google authentication
    const token = jwt.sign(
      {
        userId: req.user._id,
        accessToken: req.user.accessToken,
        role: req.user.role,
        username: req.user.username,
        googleId: req.user.googleId, // Adjust as per your schema
      },
      process.env.JWT_PASSPHRASE,
      {
        expiresIn: "24h", // Adjust expiration as needed
      }
    );

    // Set the token in a cookie (assuming you want to store it this way)
    res.cookie("token", token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours expiration
      path: "/",
    });

    // Redirect to the desired route after successful authentication
    res.redirect("/google"); // This should redirect to /google
  }
);
app.get("/google", ensureAuthenticated, async (req, res) => {
  const token = req.cookies.token; // Assuming token is stored in a cookie

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_PASSPHRASE);

    // Fetch user details based on decoded payload
    const userId = decoded.userId;
    const user = await AccountModel.findById(userId);

    if (!user) {
      throw new Error("User not found");
    }

    res.json({ message: `Welcome ${user.username}`, user: req.user });
  } catch (error) {
    console.error("Token verification failed:", error.message);
    res.status(401).json({ message: "Unauthorized" });
  }
});

// GitHub  Initiate authentication with 
app.get("/auth/github", passport.authenticate("github"));
// GitHub callback handler
app.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/login" }),
  function (req, res) {
    // Generate JWT token after successful GitHub authentication
    const token = jwt.sign(
      {
        userId: req.user._id,
        accessToken: req.user.accessToken,
        role: req.user.role,
        username: req.user.username,
        otherId: req.user.otherId,
      },
      process.env.JWT_PASSPHRASE,
      {
        expiresIn: "24h", // Adjust expiration as needed
      }
    );

    // Set the token in a cookie (assuming you want to store it this way)
    res.cookie("token", token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // Example: 24 hours expiration
      path: "/", // Ensure cookie is accessible across the entire site
    });

    // Redirect to a protected route or respond with JSON data
    res.redirect("/github");
  }
);
app.get("/github", ensureAuthenticated, async (req, res) => {
  const token = req.cookies.token; // Assuming token is stored in a cookie

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_PASSPHRASE);

    // Fetch user details based on decoded payload
    const userId = decoded.userId;
    const user = await AccountModel.findById(userId);

    if (!user) {
      throw new Error("User not found");
    }

    res.json({ message: `Welcome ${user.username}`, user: req.user });
  } catch (error) {
    console.error("Token verification failed:", error.message);
    res.status(401).json({ message: "Unauthorized" });
  }
});

// LEARN: How to use cookies in Express
app.get("/demoCookie", (req, res, next) => {
  const pathCookie = path.join(__dirname, "demoCookie.html");
  res.sendFile(pathCookie);
});

// private route
app.get(
  "/private",
  async (req, res, next) => {
    try {
      const token = req.cookies.token;
      if (!token) {
        throw new Error("Token not found in cookies");
      }
      const result = jwt.verify(token, JWT_PASSPHRASE);
      const account = await AccountModel.findOne({ _id: result._id });
      if (!account) {
        throw new Error("Account not found");
      }
      res.username = account.username;
      next();
    } catch (error) {
      console.error("Error:", error.message);
      return res.redirect("/login"); // Redirect to login page on error
    }
  },
  (req, res, next) => {
    res.json("Welcome " + res.username);
  }
);

app.get("/task", checkLogin, (req, res, next) => {
  res.json("Welcome ALL Tasks");
});
// student route
app.get(
  "/student",
  checkLogin,
  checkTeacher,
  (req, res, next) => {
    try {
      next();
    } catch (error) {
      console.error("Error:", error.message);
    }
  },
  (req, res, next) => {
    res.json("Student");
  }
);
// teacher route
app.get(
  "/teacher",
  checkLogin,
  checkManager,
  (req, res, next) => {
    try {
      next();
    } catch (error) {
      console.error("Error:", error.message);
    }
  },
  (req, res, next) => {
    res.json("Teacher");
  }
);

app.get("/home", checkLogin, (req, res, next) => {
  const pathHome = path.join(__dirname, "home.html");
  res.sendFile(pathHome);
});

app.get("/accounts", async (req, res, next) => {
  const { page = 1, limit = 1 } = req.query;
  try {
    const options = {
      page: parseInt(page, 10),
      limit: parseInt(limit, 10),
    };
    const accounts = await AccountModel.paginate({}, options);
    res.json(accounts);
  } catch (err) {
    console.error("Error fetching accounts:", err);
    res.status(500).send("Server Error");
  }
});

app.use("/api/v1/", router1);
app.use("/api/account/", accountRouter);

// Access the session as req.session
app.get("/demoSession", (req, res, next) => {
  if (req.session.views) {
    req.session.views++;
    res.setHeader("Content-Type", "text/html");
    res.write("<p>views: " + req.session.views + "</p>");
    res.write("<p>expires in: " + req.session.cookie.maxAge / 1000 + "s</p>");
    res.end();
  } else {
    req.session.views = 1;
    res.end("welcome to the session. refresh!");
  }
});

app.post("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      console.error("Error logging out:", err);
      return res.status(500).json({ error: "Error logging out" });
    }
    req.session.destroy(function (err) {
      if (!err) {
        res.clearCookie("connect.sid"); // Clear session cookie
        res.clearCookie("token"); // Clear token cookie if exists
        res.redirect("/login"); // Redirect to login page after logout
      } else {
        console.error("Error destroying session:", err);
        res.status(500).json({ error: "Error logging out" });
      }
    });
  });
});
// STEP 7: 2FA by Microsoft or Google - Function to generate OTP Auth URL
// 2FA by Microsoft or Google - Function to generate OTP Auth URL
function generateOTPAuthURL(username, secret) {
  return `otpauth://totp/${username}?secret=${secret}&issuer=Demo2FA`;
}
// 2FA by Microsoft or Google -  Function to generate OTP secret
function generateOTPSecret() {
  return speakeasy.generateSecret({ length: 20 });
}
// 2FA by Microsoft or Google -  Function to create QR code for OTP secret
function generateQRCode(url, callback) {
  QRCode.toDataURL(url, (err, data) => {
    if (err) {
      console.error("Error generating QR code:", err);
      callback(err);
    } else {
      callback(null, data);
    }
  });
}
// STEP 4: Must login first and use this link to create QR code image for scanning
// to register with an authenticator app (Google Authenticator or Microsoft Authenticator)
app.get("/generate-otp", async (req, res) => {
  try {
    const user = await AccountModel.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Generate a secret for the user
    const secret = generateOTPSecret();

    // Save the OTP secret securely for the user (e.g., in database)
    user.otpSecret = secret.base32;
    await user.save();

    // Generate an OTP authentication URL
    const otpAuthURL = generateOTPAuthURL(req.user.username, secret.base32);

    // Generate QR code for OTP secret
    generateQRCode(otpAuthURL, (err, qrCodeData) => {
      if (err) {
        return res.status(500).json({ error: "Error generating QR code" });
      }
      res.send(`<img src="${qrCodeData}">`);
    });
  } catch (err) {
    console.error("Error generating OTP:", err);
    res.status(500).json({ error: "Error generating OTP" });
  }
});
// STEP 4: Create the QR to scan without login, just using username as below
// Guide got to link to get qr-code http://localhost:3000/qr-code?username=tuphung010787@gmail.com
// Scan this QR code with an authenticator app like Google Authenticator or Microsoft Authenticator

app.get("/qr-code", async (req, res) => {
  try {
    console.log("req.query:", req.query);
    const username = req.query.username;
    const user = await AccountModel.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const secret = generateOTPSecret();
    user.otpSecret = secret.base32;
    await user.save();

    const otpAuthURL = generateOTPAuthURL(username, secret.base32);
    generateQRCode(otpAuthURL, (err, qrCodeData) => {
      if (err) {
        return res.status(500).json({ error: "Error generating QR code" });
      }
      res.type("png");
      res.send(Buffer.from(qrCodeData.split("base64,")[1], "base64"));
    });
  } catch (err) {
    console.error("Error generating QR code:", err);
    res.status(500).json({ error: "Error generating QR code" });
  }
});
// STEP 5: 2FA by Microsoft or Google - route to verify OTP
app.post("/verify-otp", async (req, res) => {
  try {
    const { username, otp } = req.body;
    const user = await AccountModel.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const verified = speakeasy.totp.verify({
      secret: user.otpSecret,
      encoding: "base32",
      token: otp,
      window: 1, // Allow 1-time 30-second step validation code
    });

    if (verified) {
      // OTP verification successful
      res.json({ message: "OTP verification successful" });
    } else {
      // OTP verification failed
      res.status(401).json({ error: "Invalid OTP" });
    }
  } catch (err) {
    console.error("Error verifying OTP:", err);
    res.status(500).json({ error: "Error verifying OTP" });
  }
});

// DEBUG: use Twilio for sending OTPs via SMS or voice calls, you need to follow these steps to set up and configure Twilio
// 2FA Twilio by SMS and Calling - Function to send OTP via SMS
function generateOTPTwilio() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}
// 2FA Twilio by SMS and Calling - route to send OTP via SMS
app.post("/send-otpTwilio", async (req, res) => {
  try {
    const { username, phoneNumber, method } = req.body; // method can be 'sms' or 'call'

    const user = await AccountModel.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const otp = generateOTPTwilio();

    // Save the OTP in the user's record in the database
    user.otp = otp;
    await user.save();

    // Send OTP via SMS or call
    if (method === "sms") {
      await twilioClient.messages.create({
        body: `Your verification code is ${otp}`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phoneNumber,
      });
    } else if (method === "call") {
      await client.calls.create({
        twiml: `<Response><Say>Your verification code is ${otp}</Say></Response>`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phoneNumber,
      });
    }

    res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("Error sending OTP:", err);
    res.status(500).json({ error: "Error sending OTP" });
  }
});
// 2FA Twilio by SMS and Calling - Example route to verify OTP
app.post("/verify-smsTwilio", async (req, res) => {
  try {
    const { username, otp } = req.body;

    const user = await AccountModel.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (user.otp === otp) {
      // OTP verification successful
      user.otp = null; // Clear the OTP after successful verification
      await user.save();
      res.json({ message: "OTP verification successful" });
    } else {
      // OTP verification failed
      res.status(401).json({ error: "Invalid OTP" });
    }
  } catch (err) {
    console.error("Error verifying OTP:", err);
    res.status(500).json({ error: "Error verifying OTP" });
  }
});

//STEP 2: SMS OTP phone
app.get("/smsOTP", (req, res, next) => {
  const pathSmsOtp = path.join(__dirname, "smsOTP.html");
  res.sendFile(pathSmsOtp);
});
app.post("/send-otp", async (req, res) => {
  const phoneNumber = req.body.phoneNumber;
  try {
    // Server-side appVerifier setup not required for client-side RecaptchaVerifier
    req.session.verificationId = null; // Clear any previous session
    res.status(200).send({
      message:
        "OTP request received. Please complete reCAPTCHA and OTP on the client side.",
    });
  } catch (error) {
    console.error("Error during send OTP:", error);
    res.status(500).send({ error: error.message });
  }
});
app.post("/verify-otp", async (req, res) => {
  const { otp } = req.body;
  const verificationId = req.session.verificationId;

  try {
    if (!verificationId) {
      throw new Error("Verification ID not found in session.");
    }
    const credential = admin.auth.PhoneAuthProvider.credential(
      verificationId,
      otp
    );
    const userCredential = await admin.auth().signInWithCredential(credential);
    res.status(200).send({ user: userCredential.user });
  } catch (error) {
    console.error("Error during OTP verification:", error);
    res.status(500).send({ error: error.message });
  }
});

//STEP 3: Email OTP
app.get("/emailOTP", (req, res, next) => {
  const pathEmailOtp = path.join(__dirname, "emailOTP.html");
  res.sendFile(pathEmailOtp);
});
// Email Generate and send OTP
app.post("/sendOtpEmail", (req, res) => {
  const email = req.body.email;
  const otp = Math.floor(100000 + Math.random() * 900000); // 6 digit OTP
  otpStore[email] = otp;

  const mailOptions = {
    from: process.env.GMAIL_USER,
    to: email,
    subject: "Email OTP",
    text: `OTP is ${otp}`,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log(error);
      res.status(500).send("Error sending email");
    } else {
      console.log("Email sent: " + info.response);
      res.send("OTP sent to your email");
    }
  });

  // Optionally, set a timeout to invalidate the OTP
  setTimeout(() => delete otpStore[email], 300000); // 5 minutes
});
// Verify OTP
app.post("/verifyOtpEmail", (req, res) => {
  const { email, otp } = req.body;
  if (otpStore[email] && otpStore[email] == otp) {
    res.send("OTP verified successfully");
  } else {
    res.status(400).send("Invalid OTP");
  }
});

app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
