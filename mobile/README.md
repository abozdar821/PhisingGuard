# PhishGuard mobile

Expo (React Native) app for iOS and Android. It calls the deployed PhishGuard web API (`/api/scan` and `/api/extract`), so the Vercel app must be live with `ANTHROPIC_API_KEY` set.

## Run on your phone

1. Install **Expo Go** from the App Store or Google Play.
2. Point the app at your deployment:
   ```bash
   cp .env.example .env.local   # then set EXPO_PUBLIC_API_URL to your Vercel URL
   ```
3. Start it:
   ```bash
   npm install
   npx expo start
   ```
4. Scan the QR code with your phone camera (iOS) or the Expo Go app (Android).

## Build installable apps

```bash
npm install -g eas-cli
eas build --platform android   # .apk / .aab
eas build --platform ios       # needs an Apple Developer account
```
