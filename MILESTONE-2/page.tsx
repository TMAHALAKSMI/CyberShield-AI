"use client";
import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Navbar } from "@/components/navbar";
import { HeroSection, type ScanResult } from "@/components/hero-section";
import { ShieldCheck, Zap, Globe, Lock, Mail, Github, FileText } from "lucide-react";

export default function Home() {
  const [lastResult, setLastResult] = useState<ScanResult | null>(null);
  const [username, setUsername] = useState("");
  const router = useRouter();

  useEffect(() => {
    const user = localStorage.getItem("username");
    if (!user) router.push("/login");
    else setUsername(user);
  }, [router]);

  return (
    <div className="min-h-screen bg-white flex flex-col">
      <Navbar />
      <main className="grow pt-20">
        <HeroSection username={username} onScanComplete={(res) => setLastResult(res)} />

        {lastResult && (
          <div className="container px-6 mb-12">
            <div className={`max-w-6xl mx-auto p-6 rounded-2xl border-2 flex items-start gap-4 ${
              lastResult.is_phishing ? "bg-red-50 border-red-200" : "bg-green-50 border-green-200"
            }`}>
              <ShieldCheck className={lastResult.is_phishing ? "text-red-600" : "text-green-600"} size={32} />
              <div>
                <h3 className="text-xl font-bold">{lastResult.is_phishing ? "Phishing URL" : "Safe URL"}</h3>
                <p className="text-sm opacity-70">{lastResult.url}</p>
                <p className="font-bold">Confidence: {(lastResult.confidence * 100).toFixed(2)}%</p>
              </div>
            </div>
          </div>
        )}

        <section className="container px-6 py-12 grid grid-cols-1 md:grid-cols-4 gap-6 max-w-7xl mx-auto">
          <FeatureCard icon={<Zap className="text-green-500" />} title="Real-time Detection" desc="Scan URLs instantly." />
          <FeatureCard icon={<ShieldCheck className="text-green-500" />} title="ML-Powered" desc="99% detection accuracy." />
          <FeatureCard icon={<Globe className="text-green-500" />} title="Global Intel" desc="Stay protected globally." />
          <FeatureCard icon={<Lock className="text-green-500" />} title="Privacy First" desc="Your data stays private." />
        </section>
      </main>

      <footer className="bg-slate-50 border-t py-12 mt-auto">
        <div className="container px-6 max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-12">
          <div>
            <div className="flex items-center gap-2 mb-4"><ShieldCheck className="text-green-600"/><span className="font-bold">CyberShield AI</span></div>
            <p className="text-slate-500 text-sm">AI-powered phishing detection. Keeping the internet safe.</p>
          </div>
          <div>
            <h4 className="font-bold mb-4">Quick Links</h4>
            <ul className="text-sm text-slate-500 space-y-2"><li>Home</li><li>About</li><li><button onClick={()=>router.push("/dashboard")}>Dashboard</button></li></ul>
          </div>
          <div>
            <h4 className="font-bold mb-4">Contact</h4>
            <ul className="text-sm text-slate-500 space-y-2"><li className="flex gap-2"><Mail size={16}/> contact@cybershield.ai</li></ul>
          </div>
        </div>
      </footer>
    </div>
  );
}

function FeatureCard({ icon, title, desc }: any) {
  return (
    <div className="p-8 border rounded-2xl bg-white shadow-sm hover:shadow-md transition-all">
      <div className="mb-4">{icon}</div>
      <h3 className="font-bold text-lg">{title}</h3>
      <p className="text-slate-500 text-sm">{desc}</p>
    </div>
  );
}
