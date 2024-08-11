import mongoose from "mongoose";
import mongoosePaginate from "mongoose-paginate-v2";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI;

mongoose
  .connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log("MongoDB connected successfully");
  })
  .catch((err) => {
    console.error("Error connecting to MongoDB:", err);
  });

const { Schema } = mongoose;

const AccountSchema = new Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      enum: ["user", "manager", "teacher"],
      default: "user",
    },
    otherId: {
      type: String,
      unique: true,
      sparse: true,
    },
    accessToken: {
      type: String,
    },
    email: {
      type: String,
      unique: true,
      match: [/^\S+@\S+\.\S+$/, "Please fill a valid email address"],
    },
    photos: {
      type: [String],
    },
    otpSecret: {
      type: String,
    },
    optSMS: {
      type: String,
    },
    phone: {
      type: String,
      unique: true,
      required: true,
      match: [/^\+[1-9]\d{1,14}$/, "Please fill a valid phone number"],
    },
  },
  {
    collection: "account",
    timestamps: true,
  }
);

AccountSchema.pre("save", async function (next) {
  try {
    if (!this.isModified("password")) {
      return next();
    }
    const hashedPassword = await bcrypt.hash(this.password, 10);
    this.password = hashedPassword;
    return next();
  } catch (err) {
    return next(err);
  }
});

AccountSchema.methods.comparePassword = async function (candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (err) {
    throw new Error(err);
  }
};

AccountSchema.plugin(mongoosePaginate);

const AccountModel = mongoose.model("Account", AccountSchema);

export default AccountModel;
