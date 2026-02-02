import mongoose, { Schema } from "mongoose";
import dotenv from "dotenv";

dotenv.config();

export const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      lowercase: true,
      unique: true,
      match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
      select: false, // не возвращать в ответах
    },
    username: {
      type: String,
      required: true,
      minlength: 3,
      trim: true,
      unique: true,
    },
    profile: {
      firstName: String,
      lastName: String,
      bio: String,
    },
    isEmailVerified: { type: Boolean, default: false },
    emailVerificationToken: String,
    refreshToken: {
      type: [String],
      default: []
    },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    followers: [
      {
        type: Schema.Types.ObjectId,
        ref: "User",
        default: [],
      },
    ],
    following: [
      {
        type: Schema.Types.ObjectId,
        ref: "User",
        default: [],
      },
    ],
  },
  { timestamps: true },
);

export default mongoose.model("User", userSchema);

let uri = process.env.MONGODB_URI!;

if (!uri) {
  throw new Error("MONGODB_URI is not defined");
}

export async function connectToDb() {
  await mongoose.connect(uri);

  console.log("MongoDB connected");

  mongoose.connection.on("error", (err: string) => {
    console.error("MongoDB connection error:", err);
  });

  mongoose.connection.on("disconnected", () => {
    console.warn("MongoDB disconnected");
  });
}
