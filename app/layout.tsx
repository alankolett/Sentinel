import type { Metadata, Viewport } from "next";
import { Inter, Fraunces } from "next/font/google";
import "./globals.css";
import { StoreProvider } from "@/lib/store";
import { Sidebar, MobileNav } from "@/components/shell";
import { IntroAnimation } from "@/components/IntroAnimation";

// Applied before paint to avoid a theme flash. Dark is the default for SIH demo.
const themeScript = `(function(){try{var t=localStorage.getItem('sentinel-theme');document.documentElement.setAttribute('data-theme',t==='light'?'light':'dark');}catch(e){document.documentElement.setAttribute('data-theme','dark');}})();`;

const inter = Inter({ subsets: ["latin"], variable: "--font-sans", display: "swap" });
const fraunces = Fraunces({ subsets: ["latin"], variable: "--font-serif", display: "swap", axes: ["opsz"] });

export const metadata: Metadata = {
  title: "Sentinel — Network Attack Forecasting",
  description:
    "Sentinel is an AI Network World Model that learns traffic state-transition dynamics P(Sₜ₊₁|Sₜ) and forecasts attack progression before compromise. SIH26153 · NTRO.",
  applicationName: "Sentinel",
  robots: { index: true, follow: true },
  authors: [{ name: "Sentinel" }],
  keywords: ["network attack forecasting", "world model", "MITRE ATT&CK", "intrusion prediction", "SIH26153", "NTRO"],
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#faf9f5" },
    { media: "(prefers-color-scheme: dark)", color: "#080b12" },
  ],
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="dark" className={`${inter.variable} ${fraunces.variable}`} suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>
        <StoreProvider>
          <IntroAnimation />
          <div className="shell">
            <Sidebar />
            <div className="main-col">
              <MobileNav />
              <main className="main">{children}</main>
            </div>
          </div>
        </StoreProvider>
      </body>
    </html>
  );
}
