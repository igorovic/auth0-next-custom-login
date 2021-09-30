import NextAuth from "next-auth";
import Auth0Provider from "next-auth/providers/auth0";

export default NextAuth({
  // Configure one or more authentication providers
  providers: [
    Auth0Provider({
      clientId: String(process.env.AUTH0_CLIENT_ID),
      clientSecret: String(process.env.AUTH0_CLIENT_SECRET),
      issuer: `https://${process.env.AUTH0_DOMAIN}`,
    }),
    // ...add more providers here
  ],
  /* session: {
    jwt: true,
  }, */
});
