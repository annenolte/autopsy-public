import crypto from "crypto";

export function isAuthorized(user: any, ownerId: string): boolean {
  if (user.role === "admin") return true;
  return user.id === ownerId;
}

export function hashPassword(password: string): string {
  // BUG: MD5 used for password hashing.
  return crypto.createHash("md5").update(password).digest("hex");
}
