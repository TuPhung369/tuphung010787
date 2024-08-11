import jwt from "jsonwebtoken";
import fs from "fs";

var privateKey = fs.readFileSync("./key/private.pem", "utf8");

// Set token to expire in 1 day
var token = jwt.sign({ username: "TOMMEM", password: "12345" }, privateKey, {
  algorithm: "RS256",
  expiresIn: "1d",
});

//console.log("Token:", token);

var tokenDecoded = token;

// verify a token asymmetric
var cert = fs.readFileSync("./key/publickey.crt", "utf8"); // get public key
jwt.verify(tokenDecoded, cert, { algorithms: ["RS256"] }, function (err, data) {
  if (err) {
    console.error("Token verification failed:", err);
  } else {
    console.log("Decoded data:", data); // bar
  }
});

// HMAC Algorithms:
// HS256 - HMAC using SHA-256 hash algorithm
// HS384 - HMAC using SHA-384 hash algorithm
// HS512 - HMAC using SHA-512 hash algorithm
// RSA Algorithms:
// RS256 - RSASSA-PKCS1-v1_5 using SHA-256 hash algorithm
// RS384 - RSASSA-PKCS1-v1_5 using SHA-384 hash algorithm
// RS512 - RSASSA-PKCS1-v1_5 using SHA-512 hash algorithm
// RSASSA-PSS Algorithms:
// PS256 - RSASSA-PSS using SHA-256 hash algorithm
// PS384 - RSASSA-PSS using SHA-384 hash algorithm
// PS512 - RSASSA-PSS using SHA-512 hash algorithm
// ECDSA Algorithms:
// ES256 - ECDSA using P-256 curve and SHA-256 hash algorithm
// ES384 - ECDSA using P-384 curve and SHA-384 hash algorithm
// ES512 - ECDSA using P-521 curve and SHA-512 hash algorithm
// EdDSA Algorithm:
// EdDSA - EdDSA algorithm, such as Ed25519 and Ed448
