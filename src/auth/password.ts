// import crypto from 'crypto';

// // Inside your Express route:
// const email = req.body.email;
// const token = crypto.randomBytes(32).toString('hex');
// const expiry = new Date(Date.now() + 3600000); // Expires in 1 hour

// // Update the user in Postgres
// await pool.query(
//   'UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3',
//   [token, expiry, email]
// );

// // TODO: Send the email with the link: 
// // http://localhost:5173/reset-password?token=${token}