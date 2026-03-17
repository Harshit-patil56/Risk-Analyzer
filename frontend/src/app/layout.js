import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

export const metadata = {
  title: "Risk Analyzer — Phishing Detection & Risk Scoring",
  description: "Scan URLs and emails for phishing threats. Get clear risk scores, threat indicators, and educational feedback to protect yourself online.",
  icons: {
    icon: "/shield.svg",
    shortcut: "/shield.svg",
    apple: "/shield.svg",
  },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${inter.variable} antialiased`} suppressHydrationWarning>
        {children}
      </body>
    </html>
  );
}
