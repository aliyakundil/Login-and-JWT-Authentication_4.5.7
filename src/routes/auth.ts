import express from "express";
import { Router } from "express";
import type { Response, Request } from "express";
import jwt from "jsonwebtoken";
import User from "../models/User.js";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import { registerUser } from "../services/registrationService.js";
import {
  getUsers,
  getUserById,
  createUser,
  updateUser,
  patchUser,
  deleteUser,
  followUser,
  unfollowUser,
} from "../services/userServices.js";

const routes = Router();

dotenv.config();

let refreshTokens: any = [];

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

routes.post("/register", async (req, res) => {
  const { email, password, username, profile, isEmailVerified } = req.body;
  const { firstName, lastName, bio } = profile || {};

  const users = await registerUser(req.body);

  if (!email || !password || !username) {
    return res.status(400).send({ error: "Missing required fields" });
  }

  if (!users) return null;

  const userDto = {
    email: email,
    username: username,
    isEmailVerified: isEmailVerified,
    profile: profile,
  };

  res.status(201).send(userDto);
});

routes.get("/verify-email", async (req, res) => {
  const token = req.query.token as string;

  if (!token || typeof token !== "string") {
    return res.status(400).json({ message: "Token is required" });
  }

  const user = await User.findOne({
    emailVerificationToken: token,
  });

  if (!user) {
    return res.status(400).json({ message: "Invalid token" });
  }

  user.isEmailVerified = true;
  user.emailVerificationToken = null;
  await user.save();

  res.send("Email verified successfully");
});

routes.post("/resend-verification", async (req, res) => {
  const { email } = req.body;

  const userEmail = await User.findOne({
    email: email,
  });
  if (!userEmail) {
    return res.status(404).json({ message: "User not found" });
  }

  const payload = { userId: userEmail._id };

  const accessToken = jwt.sign(payload, ACCESS_TOKEN_SECRET!, {
    expiresIn: "30m",
  }); // уникальный токен
  const refreshToken = jwt.sign(payload, REFRESH_TOKEN_SECRET!, {
    expiresIn: "7d",
  });

  userEmail.refreshToken = refreshToken;

  res.json({
    message: "Verification tokens generated",
    accessToken,
    refreshToken,
  });
});

function generateAccessToken(user: any) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET!, { expiresIn: "60s" });
}

routes.post("/login", async (req: Request, res: Response) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email }).select("+password");

  if (!user) {
    return res.status(401).json({ msg: "Invalid credentials" });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const payload = {
    userId: user._id,
    role: user.role,
  };

  const accessToken = generateAccessToken(user);
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET!);

  refreshTokens.push(refreshToken);
  await user.save();

  res.json({ accessToken, refreshToken });
});

routes.post("/token", (req: Request, res: Response) => {
  const refreshToken = req.body.token;
  if (!refreshToken) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);

  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SCRET!,
    (err: any, decoded: any) => {
      if (err) return res.sendStatus(403);

      const payload = {
        userId: decoded.userId,
        role: decoded.role,
      };

      const newAccessToken = generateAccessToken({ name: payload });
      res.json({ accessToken: newAccessToken });
    },
  );
});

routes.delete("/logout", (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((f: any) => f !== refreshToken);
  res.sendStatus(204);
});

const router = express.Router();

router.get("/users", async (req, res, next) => {
  try {
    const user = await getUsers(req.query);
    res.status(200).json({ success: true, data: user });
  } catch (err) {
    next(err);
  }
});

router.get("/users/:id", async (req, res, next) => {
  try {
    const id = req.params.id;

    if (!id) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    const result = await getUserById(id);

    if (!result) {
      return res.status(404).json({
        success: false,
        error: "Invalid user id",
      });
    }

    res.status(200).json({ success: true, data: result });
  } catch (err) {
    next(err);
  }
});

router.post("/users", async (req, res, next) => {
  try {
    const result = await createUser(req.body);
    res.status(201).json({ success: true, data: result });
  } catch (err) {
    next(err);
  }
});

router.put("/users/:id", async (req, res, next) => {
  try {
    const id = req.params.id;
    const result = await updateUser(id, req.body);

    if (!result) {
      return res.status(404).json({
        success: false,
        error: "User not found",
      });
    }

    res.status(200).json({ success: true, data: result });
  } catch (err) {
    next(err);
  }
});

router.patch("/users/:id", async (req, res, next) => {
  try {
    const id = req.params.id;

    const body = req.body;

    if (!body || Object.keys(body).length === 0) {
      const err = new Error("Body не может быть пустым");
      (err as any).status = 400;
      return next(err);
    }

    const result = await patchUser(id, req.body);

    if (!result) {
      const err = new Error("Not Found");
      (err as any).status = 400;
      return next(err);
    }

    res.status(200).json({ success: true, data: result });
  } catch (err) {
    next(err);
  }
});

router.delete("/users/:id", async (req, res, next) => {
  try {
    const id = req.params.id;
    const deleted = await deleteUser(id);

    if (!deleted) {
      const err = new Error("User not found");
      (err as any).status = 404;
      return next(err);
    }

    return res.status(204).send();
  } catch (err) {
    next(err);
  }
});

router.post("/users/:id/follow", async (req, res, next) => {
  try {
    const targetUserId = req.params.id;
    const currentUserId = req.body.userId;

    if (!currentUserId) {
      const err = new Error("User ID is required to like post");
      (err as any).status = 400;
      return next(err);
    }

    if (currentUserId === targetUserId) {
      const err = new Error("You cannot follow yourself");
      (err as any).status = 400;
      return next(err);
    }

    const result = await followUser(targetUserId, currentUserId);

    res.status(201).json({
      success: true,
      data: result.following,
      followersCount: result.following.followers.length,
      followed: result.followed,
    });
  } catch (err) {
    next(err);
  }
});

router.post("/users/:id/unfollow", async (req, res, next) => {
  try {
    const targetUserId = req.params.id;
    const currentUserId = req.body.userId;

    if (!currentUserId) {
      const err = new Error("User ID is required to like post");
      (err as any).status = 400;
      return next(err);
    }

    if (currentUserId === targetUserId) {
      const err = new Error("You cannot unfollow yourself");
      (err as any).status = 400;
      return next(err);
    }

    const result = await unfollowUser(currentUserId, targetUserId);

    res.status(201).json({
      success: true,
      data: result.following,
      followersCount: result.following.followers.length,
      unfollowed: result.follower,
    });
  } catch (err) {
    next(err);
  }
});

export default router;
