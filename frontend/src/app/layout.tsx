import type { Metadata } from "next";
import { Plus_Jakarta_Sans, Geist } from "next/font/google";
import "./globals.css";
import PWARegistration from "@/components/PWARegistration";
import { cn } from "@/lib/utils";

const geist = Geist({subsets:['latin'],variable:'--font-sans'});

const plusJakartaSans = Plus_Jakarta_Sans({
  subsets: ["latin"],
  variable: "--font-plus-jakarta",
  weight: ["400", "500", "600", "700", "800"],
});

export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL || "https://phishguard.tech"),
  title: {
    default: "PhishGuard - AI-Powered Phishing Detection & Form Security",
    template: "%s | PhishGuard"
  },
  description: "Protect yourself from phishing threats. PhishGuard uses real-time AI to detect malicious URLs and secure application submissions.",
  keywords: ["phishing detection", "AI link scanner", "secure forms", "malicious URL checker", "cybersecurity", "PWA security"],
  authors: [{ name: "PhishGuard Team" }],
  manifest: "/manifest.json",
  icons: {
    icon: [
      { url: "/favicon.ico?v=1", sizes: "any" },
      { url: "/icons/icon-192.png?v=1", type: "image/png", sizes: "192x192" },
    ],
    shortcut: "/favicon.ico?v=1",
    apple: "/icons/icon-192.png?v=1",
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: process.env.NEXT_PUBLIC_SITE_URL || "https://phishguard.tech",
    title: "PhishGuard - AI-Powered Phishing Detection & Form Security",
    description: "Protect yourself from phishing threats. PhishGuard uses real-time AI to detect malicious URLs and secure application submissions.",
    siteName: "PhishGuard",
    images: [
      {
        url: "/og-image.png",
        width: 1200,
        height: 630,
        alt: "PhishGuard - Real-Time Phishing Link & Form Security",
      }
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "PhishGuard - AI-Powered Phishing Detection & Form Security",
    description: "Protect yourself from phishing threats. PhishGuard uses real-time AI to detect malicious URLs and secure application submissions.",
    images: ["/og-image.png"],
  },
};

export const viewport = {
  themeColor: "#064e3b",
  width: "device-width",
  initialScale: 1.0,
  maximumScale: 1.0,
  userScalable: false,
  viewportFit: "cover",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={cn("h-full", plusJakartaSans.variable, "font-sans", geist.variable)}>
      <body className="min-h-full flex flex-col">
        <PWARegistration />
        {children}
      </body>
    </html>
  );
}

