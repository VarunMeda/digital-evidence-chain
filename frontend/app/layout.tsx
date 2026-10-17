import "./globals.css";
export const metadata = { title: "Evidence Chain", description: "Digital evidence chain management" };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) { return <html lang="en"><body>{children}</body></html>; }
