import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'CyberShield AI',
  description: 'ML-Powered Phishing URL Detection',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
