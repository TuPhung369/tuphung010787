import admin from "firebase-admin";
import dotenv from "dotenv";
dotenv.config();

// Path to your Firebase private key JSON file
import serviceAccount from "./key/serviceAccountKey.json" assert { type: "json" };

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL, // Add your database URL if you have one
});

export default admin;
