import pkg from "pg";
const { Pool } = pkg;

export const pool = new Pool({
  user: "postgres",
  host: "localhost",
  database: "auth_demo",
  password: "yourpassword",
  port: 5432,
});