import express from "express";
const router = express.Router();
import AccountModel from "../models/account.js";

// get data from DB
router.get("/", (req, res, next) => {
  AccountModel.find({})
    .then((data) => {
      res.json(data);
    })
    .catch((err) => {
      res.status(500).json("Error getting data from DB");
    });
});
router.get("/:id", (req, res, next) => {
  const { id } = req.params;
  AccountModel.findById({ _id: id }, {}) //findOne can find any field, findById can only find by id
    .then((data) => {
      res.json(data);
    })
    .catch((err) => {
      res.status(500).json("Error getting data from DB");
    });
});
// add new data in DB
router.post("/", (req, res, next) => {
  const { username, password } = req.body;
  AccountModel.create({
    username: username,
    password: password,
  })
    .then((data) => {
      res.json("Account created successfully");
    })
    .catch((err) => {
      res.status(500).json("Error creating account");
    });
});
// Update data in DB
router.put("/:id", (req, res, next) => {
  const { id } = req.params;
  const { username, password, role, phone } = req.body;

  const updateData = {};
  if (username) updateData.username = username;
  if (password) updateData.password = password;
  if (role) updateData.role = role;
  if (phone) updateData.phone = phone;

  AccountModel.findByIdAndUpdate(id, updateData, { new: true })
    .then((data) => {
      if (!data) {
        return res.status(404).json("Account not found");
      }
      res.json("Account updated successfully");
    })
    .catch((err) => {
      console.error("Error updating account:", err);
      res.status(500).json("Error updating account");
    });
});

// delete data in DB
router.delete("/:id", (req, res, next) => {
  const { id } = req.params;
  AccountModel.findByIdAndDelete(id).then((data) => {
    if (!data) {
      return res.status(404).json("Account not found");
    }
    res.json("Account deleted successfully");
  });
});

export default router;
