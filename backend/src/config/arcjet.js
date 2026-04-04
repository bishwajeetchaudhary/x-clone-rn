import arcjet, { tokenBucket, shield, detectBot } from "@arcjet/node";
import { ENV } from "./env.js";

// imitialize Arcjet with security rules
export const aj = arcjet({
  key: ENV.ARCJET_KEY,
  characteristics: ["ip.src"],
  rules: [
    // shield protects our app from common attacks eg. SQL injection, XSS, CSRF attacks, etc
    shield({ mode: "LIVE" }),

    // bot detection - block all bots excrpt search encines
    detectBot({
      mode: "LIVE",
      allow: [
        "CATEGORY:SEARCH_ENGINE",
        // allow legitimate search engine bots
        //full list - https://arcjet.com/bot-list
      ],
    }),

    // rate limiting with token bucket algorithm
    tokenBucket({
      mode: "LIVE",
      refillRate: 10, // token added per interval
      interval: 10, // interval in seconds (10 seconds)
      capacity: 15, // maximum tokens in the bucket
    }),
  ],
});