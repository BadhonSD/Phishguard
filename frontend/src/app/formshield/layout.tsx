import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Form Shield",
  description: "Secure and protect your submissions from phishing and malicious URLs in real-time using PhishGuard Form Shield.",
  openGraph: {
    title: "Form Shield - PhishGuard",
    description: "Secure and protect your submissions from phishing and malicious URLs in real-time using PhishGuard Form Shield.",
    images: ["/og-image.png"],
  },
  twitter: {
    title: "Form Shield - PhishGuard",
    description: "Secure and protect your submissions from phishing and malicious URLs in real-time using PhishGuard Form Shield.",
    images: ["/og-image.png"],
  },
};

export default function FormShieldLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
