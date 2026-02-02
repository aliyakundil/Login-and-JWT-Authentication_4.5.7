import express from "express";
import authRouter from "./routes/auth.js";
import { connectToDb } from "./models/User.js";
import type { Request, Response, NextFunction } from "express";

interface ApiError extends Error {
  status?: number;
}

const app = express();
const PORT = 3000;

app.use(express.json());

app.get("/", (_req: Request, res: Response) => {
  res.json({
    name: "Todo REST API",
    version: "1.0.0",
    links: {
      api: "/api",
      health: "/health",
      todos: "/api/users",
    },
  });
});

app.use("/api", authRouter);
// app.use("/api", authRouter);

export function errorHandler(
  err: ApiError,
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const status = err.status || 500;

  console.error("Error:", {
    message: err.message,
    status,
    stack: err.stack,
  });

  res.status(status).json({
    success: false,
    error: err.message,
  });
}

export function notFoundHandler(req: Request, res: Response) {
  res.status(404).json({
    success: false,
    error: "Not found!",
    message: `Route ${req.originalUrl} does not exist`,
  });
}

app.use(notFoundHandler);
app.use(errorHandler);

async function startServer() {
  try {
    await connectToDb();

    app.listen(PORT, () => {
      console.log("Server started on port 3000");
    });
  } catch (err) {
    console.log("Failed to start server: ", err);
    process.exit(1);
  }
}

startServer();
