import jwt from "jsonwebtoken";
import express from "express";

var data = { userName: "admin" };
//var token = jwt.sign(data, "tom12345");
//console.log(token);

var token =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyTmFtZSI6ImFkbWluIiwiaWF0IjoxNzE5OTg3ODMwfQ.Vt7bs1skENYreR61t01Qa2VJHXS9fFMAxEqTX8haqlY";
var result = jwt.verify(token, "tom12345");
console.log(result);
