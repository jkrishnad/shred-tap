import type { Metadata, Viewport } from "next";
import { Analytics } from "@vercel/analytics/next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import "./globals.css";

const sans = IBM_Plex_Sans({ variable: "--font-sans", subsets: ["latin"], weight: ["400", "500", "600"] });
const mono = IBM_Plex_Mono({ variable: "--font-mono", subsets: ["latin"], weight: ["400", "500"] });

export const metadata: Metadata = {
  title: "Vyra Shreds",
  description: "Live shreds reaching the Vyra Labs testnet validator, decoded on the node.",
  icons: { icon: { url: "/favicon-48.png", type: "image/png", sizes: "48x48" } },
};

// the design is light only, so browsers that darken pages on their own leave it as is
export const viewport: Viewport = { colorScheme: "light" };

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body>
        {children}
        {/* Vercel Web Analytics: page views and visitors, only counted on the Vercel deployment */}
        <Analytics />
      </body>
    </html>
  );
}
