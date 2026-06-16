import './globals.css';
import { Syne, IBM_Plex_Mono } from 'next/font/google';

const syne = Syne({ subsets: ['latin'], variable: '--font-syne', weight: ['400','600','700','800'] });
const mono = IBM_Plex_Mono({ subsets: ['latin'], variable: '--font-mono', weight: ['400','500'] });

export const metadata = {
  title: 'PhishGuard AI — Scam Detector',
  description: 'AI-powered real-time phishing, smishing, and fraud detection. Built on AWS DynamoDB + Vercel for the H01 Hackathon.',
  keywords: ['phishing', 'scam detection', 'fraud', 'cybersecurity', 'AI', 'AWS', 'DynamoDB'],
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className={`${syne.variable} ${mono.variable}`}>
      <head>
        <script src="https://accounts.google.com/gsi/client" async defer />
        <script src="https://alcdn.msauth.net/browser/2.38.0/js/msal-browser.min.js" async defer />
      </head>
      <body>{children}</body>
    </html>
  );
}
