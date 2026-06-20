import express from "express";
import { exec } from "child_process";
import { runQuery } from "./db";
import { isAuthorized, hashPassword } from "./auth";

export const router = express.Router();

router.get("/users/search", async (req, res) => {
  const q = req.query.q as string;
  // BUG: SQL injection via string concatenation, forwarded to runQuery sink.
  const sql = "SELECT * FROM users WHERE name LIKE '%" + q + "%'";
  res.json(await runQuery(sql));
});

router.put("/users/:id", async (req, res) => {
  const user = (req as any).user;
  // BUG: isAuthorized return value ignored — the check does nothing.
  isAuthorized(user, req.params.id);
  const sql =
    "UPDATE users SET name = '" + req.body.name + "' WHERE id = '" + req.params.id + "'";
  res.json(await runQuery(sql));
});

router.get("/ping", (req, res) => {
  const host = req.query.host as string;
  // BUG: OS command injection via string concatenation into exec.
  exec("ping -c 1 " + host, (err, stdout) => res.send(stdout));
});

router.get("/fetch", async (req, res) => {
  const url = req.query.url as string;
  // BUG: SSRF — fetch on a user-controlled URL with no allowlist.
  const r = await fetch(url);
  res.send(await r.text());
});

router.post("/calc", (req, res) => {
  // BUG: code injection — eval on user input.
  res.json({ result: eval(req.body.expr) });
});
