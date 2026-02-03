import bcrypt from "bcrypt";
import User from "../models/User.js";
import crypto from "crypto";

export async function registerUser(data: any) {
  const { email, password, username, profile, role } = data;

  const hashPassword = await bcrypt.hash(password, 16);

  const emailToken = crypto.randomBytes(32).toString("hex");

  const user = new User({
    email,
    password: hashPassword,
    username,
    profile,
    emailVerificationToken: emailToken,
    role,
  });

  await user.save();

  return { success: true, data: user };
}
