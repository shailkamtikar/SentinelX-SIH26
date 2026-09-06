import type { Metadata } from "next";
import { Geist, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const jetBrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SentinelX — AI-Powered Email Threat Intelligence",
  description:
    "SentinelX analyzes email evidence to support security investigations.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${jetBrainsMono.variable} h-full`}
    >
      <body className="flex h-full min-h-full flex-col bg-canvas font-sans text-text-primary antialiased">
        {children}
      </body>
    </html>
  );
}
