import mysql from "mysql2";

const conn = mysql.createConnection({ host: "localhost", user: "app" });

export function runQuery(sql: string): Promise<any> {
  // BUG: executes a raw SQL string with no parameter binding — injection sink.
  return new Promise((resolve, reject) => {
    conn.query(sql, (err: any, rows: any) => (err ? reject(err) : resolve(rows)));
  });
}
