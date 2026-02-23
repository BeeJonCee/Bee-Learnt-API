import type { Socket } from "socket.io";
import {
  extractBearerToken,
  resolveUserFromToken,
} from "../../shared/utils/auth-resolver.js";

export async function socketAuthMiddleware(
  socket: Socket,
  next: (err?: Error) => void
): Promise<void> {
  try {
    const tokenFromAuth =
      typeof socket.handshake.auth?.token === "string"
        ? extractBearerToken(socket.handshake.auth.token) ?? socket.handshake.auth.token
        : null;
    const tokenFromHeader =
      typeof socket.handshake.headers.authorization === "string"
        ? extractBearerToken(socket.handshake.headers.authorization)
        : null;
    const token = tokenFromAuth ?? tokenFromHeader;

    if (!token) {
      // Allow anonymous connections for public features
      socket.data.user = null;
      next();
      return;
    }

    socket.data.user = await resolveUserFromToken(token);
    next();
  } catch (error) {
    next(new Error("Authentication failed"));
  }
}
