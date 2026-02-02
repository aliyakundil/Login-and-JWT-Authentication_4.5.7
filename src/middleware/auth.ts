import jwt from "jsonwebtoken";
import type { JwtPayload } from "jsonwebtoken";
import type { Request, Response, NextFunction } from "express";

export interface AuthJwtPayload extends JwtPayload {
  userId: string;
  role: "user" | "admin";
}

export async function authenticateToken(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET!, (err, user) => {
    console.log("decoded token:", user);
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

export function requireRole(role: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = req.user as AuthJwtPayload | undefined;

    if (!user) return res.sendStatus(401);

    if (user.role !== role) {
      return res.sendStatus(403);
    }
    next();
  };
}
