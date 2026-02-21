export type BeeLearntRole = "STUDENT" | "PARENT" | "ADMIN" | "TUTOR";

export interface AuthUser {
  id: string;
  role: BeeLearntRole;
  email?: string;
  name?: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthUser;
    }
  }
}
