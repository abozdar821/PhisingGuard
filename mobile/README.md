# PhishGuard mobile

A native iOS and Android app (Expo) around the PhishGuard phone version. All scam rules run on the phone, as on the website, and nothing is sent to an AI service unless your own server is set up to do that.

Point it at either:
- the phone version on Vercel (`https://your-project.vercel.app`), or
- your own PhishGuard server (`python phishguard.py`, reached over HTTPS, for example with Tailscale; see `PHONE_SETUP.md`).

Links in checked messages never open inside the app. Anything outside your PhishGuard address asks first, then opens in the phone's browser.

## Run on your phone

1. Install **Expo Go** from the App Store or Google Play.
2. Set your address:
   ```bash
   cp .env.example .env.local   # then set EXPO_PUBLIC_APP_URL
   ```
3. Start it, then scan the QR code with your phone camera (iOS) or Expo Go (Android):
   ```bash
   npm install
   npx expo start
   ```

## Build installable apps

Cloud builds don't see `.env.local`, so first put your address in **both** `EXPO_PUBLIC_APP_URL` lines in `eas.json`. Then:

```bash
npx eas-cli@latest login
npx eas-cli@latest init                                   # once: links the app to your Expo account
npx eas-cli@latest build --platform android --profile preview      # .apk to install directly
npx eas-cli@latest build --platform android --profile production   # .aab for Google Play
npx eas-cli@latest build --platform ios                   # needs an Apple Developer account
```

When the build finishes, open its link on your Android phone and install the `.apk` (allow installs from your browser when asked).
