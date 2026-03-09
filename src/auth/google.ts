// // auth/google.ts
// import passport from "passport";
// import { Strategy as GoogleStrategy } from "passport-google-oauth20";

// passport.use(new GoogleStrategy({
//   clientID: process.env.GOOGLE_CLIENT_ID!,
//   clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
//   callbackURL: process.env.GOOGLE_REDIRECT_PATH,
// },
// async (_accessToken, _refreshToken, profile, done) => {
//   // profile contains user info
//   const user = {
//     googleId: profile.id,
//     email: profile.emails?.[0].value,
//     username: profile.displayName,
//   };

//   // TODO: save/find user in DB
//   return done(null, user);
// }));