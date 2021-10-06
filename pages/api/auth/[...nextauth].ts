import NextAuth from "next-auth";
import Auth0Provider from "next-auth/providers/auth0";
import CredentialsProvider from "next-auth/providers/credentials";
import { AuthenticationClient } from "auth0";
import jwksClient from "jwks-rsa";
import jwt, { JwtHeader, SigningKeyCallback } from "jsonwebtoken";
import { JWT } from "next-auth/jwt";

var client = jwksClient({
  jwksUri: `https://${String(process.env.AUTH0_DOMAIN)}/.well-known/jwks.json`,
});
function getKey(header: JwtHeader, callback: SigningKeyCallback) {
  client.getSigningKey(header.kid, function (err, key) {
    var signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

const auth0 = new AuthenticationClient({
  domain: String(process.env.AUTH0_DOMAIN),
  clientId: String(process.env.AUTH0_CLIENT_ID),
});

export default NextAuth({
  // Configure one or more authentication providers
  providers: [
    Auth0Provider({
      clientId: String(process.env.AUTH0_CLIENT_ID),
      clientSecret: String(process.env.AUTH0_CLIENT_SECRET),
      issuer: `https://${process.env.AUTH0_DOMAIN}`,
    }),
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        username: { label: "Username", type: "text", placeholder: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials, req) {
        let user = null;
        const { username, password } = credentials as {
          password: string;
          username: string;
        };
        const xRealIp = req.headers["x-real-ip"];
        let forwardedFor;
        if (Array.isArray(xRealIp)) {
          forwardedFor = xRealIp.join(",");
        } else if (xRealIp) {
          forwardedFor = xRealIp;
        }
        try {
          const R = await auth0.oauth?.passwordGrant(
            {
              realm: "Username-Password-Authentication",
              username,
              password,
            },
            forwardedFor
              ? {
                  forwardedFor,
                }
              : {}
          );
          console.debug("sign in token", R);
          let id_token: string | undefined;
          let decoded_id_token: JWT;
          if (R && R.id_token) {
            decoded_id_token = await new Promise((resolve) =>
              jwt.verify(
                String(R.id_token),
                getKey,
                { complete: true },
                function (err, decoded) {
                  if (err) {
                    console.error(err);
                  } else {
                    id_token = R.id_token;

                    resolve(decoded);
                  }
                }
              )
            );
            console.debug("T", decoded_id_token);
          }

          if (R && R.access_token) {
            const { sub, name, picture, email } = await auth0.users?.getInfo(
              R.access_token
            );
            user = {
              id: sub,
              email,
              name,
              image: picture,
              id_token: decoded_id_token,
            };
          }
          console.log("user", user);
        } catch (err) {
          console.error(err);
        }
        return user;
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      // Persist the OAuth access_token to the token right after signin
      //console.log("jwt callback", token, user);
      if (user) {
        token = user.id_token;
      }
      return token;
    },
    /* async session({ session, token, user }) {
      console.log("session callback", session, token, user);
      // Send properties to the client, like an access_token from a provider.
      session.accessToken = token.accessToken;
      return session;
    }, */
  },
  /* session: {
    jwt: true,
  }, */
});
