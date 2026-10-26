"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { 
  ShieldCheck, 
  ArrowLeft, 
  CheckCircle2, 
  AlertTriangle, 
  Loader2 
} from "lucide-react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";
// Storage Key
const STORAGE_KEY = "fs_submissions_v1";

const saveUserSubmission = (sub: any) => {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const arr = raw ? JSON.parse(raw) : [];
    arr.push(sub);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(arr));
  } catch (e) {
    console.error("Failed to save submission", e);
  }
};

// API endpoints
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const DEBOUNCE_DELAY_MS = 600;

export default function FormShield() {
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [company, setCompany] = useState("");
  const [website, setWebsite] = useState("");
  const [portfolio, setPortfolio] = useState("");
  const [message, setMessage] = useState("");

  // URL checking state
  const [websiteStatus, setWebsiteStatus] = useState<"checking" | "safe" | "unsafe" | null>(null);
  const [websiteMsg, setWebsiteMsg] = useState("");
  const [portfolioStatus, setPortfolioStatus] = useState<"checking" | "safe" | "unsafe" | null>(null);
  const [portfolioMsg, setPortfolioMsg] = useState("");

  const [isSubmitted, setIsSubmitted] = useState(false);
  const [shakeForm, setShakeForm] = useState(false);

  // Debounced validations
  useEffect(() => {
    const val = website.trim();
    if (!val) {
      setWebsiteStatus(null);
      setWebsiteMsg("");
      return;
    }
    const isUrl = /^https?:\/\//i.test(val) || /^[\w-]+(\.[\w-]+)+(\/.*)?$/i.test(val);
    if (!isUrl) {
      setWebsiteStatus("unsafe");
      setWebsiteMsg("Invalid URL format (e.g. company.com or https://company.com)");
      return;
    }

    setWebsiteStatus("checking");
    setWebsiteMsg("PhishGuard is inspecting URL…");

    const urlToCheck = /^https?:\/\//i.test(val) ? val : `http://${val}`;

    const timer = setTimeout(async () => {
      try {
        const resp = await fetch(`${API_BASE_URL}/api/check-url`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: urlToCheck }),
        });
        if (!resp.ok) throw new Error();
        const data = await resp.json();
        if (data.is_phishing) {
          setWebsiteStatus("unsafe");
          setWebsiteMsg(`Flagged as likely phishing threat! (${Math.round(data.confidence * 100)}% match)`);
        } else {
          setWebsiteStatus("safe");
          setWebsiteMsg("");
        }
      } catch (_) {
        setWebsiteStatus("unsafe");
        setWebsiteMsg("Verification check failed to connect.");
      }
    }, DEBOUNCE_DELAY_MS);

    return () => clearTimeout(timer);
  }, [website]);

  useEffect(() => {
    const val = portfolio.trim();
    if (!val) {
      setPortfolioStatus(null);
      setPortfolioMsg("");
      return;
    }
    const isUrl = /^https?:\/\//i.test(val) || /^[\w-]+(\.[\w-]+)+(\/.*)?$/i.test(val);
    if (!isUrl) {
      setPortfolioStatus("unsafe");
      setPortfolioMsg("Invalid URL format (e.g. portfolio.com or https://portfolio.com)");
      return;
    }

    setPortfolioStatus("checking");
    setPortfolioMsg("PhishGuard is inspecting URL…");

    const urlToCheck = /^https?:\/\//i.test(val) ? val : `http://${val}`;

    const timer = setTimeout(async () => {
      try {
        const resp = await fetch(`${API_BASE_URL}/api/check-url`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: urlToCheck }),
        });
        if (!resp.ok) throw new Error();
        const data = await resp.json();
        if (data.is_phishing) {
          setPortfolioStatus("unsafe");
          setPortfolioMsg(`Flagged as likely phishing threat! (${Math.round(data.confidence * 100)}% match)`);
        } else {
          setPortfolioStatus("safe");
          setPortfolioMsg("");
        }
      } catch (_) {
        setPortfolioStatus("unsafe");
        setPortfolioMsg("Verification check failed to connect.");
      }
    }, DEBOUNCE_DELAY_MS);

    return () => clearTimeout(timer);
  }, [portfolio]);

  const isSubmitBlocked =
    !fullName.trim() ||
    !email.trim() ||
    websiteStatus !== "safe" ||
    portfolioStatus !== "safe" ||
    !website.trim() ||
    !portfolio.trim();

  const handleFormSubmit = () => {
    if (!fullName || !email || !website || !portfolio) {
      setShakeForm(true);
      setTimeout(() => setShakeForm(false), 500);
      return;
    }
    if (isSubmitBlocked) {
      setShakeForm(true);
      setTimeout(() => setShakeForm(false), 500);
      return;
    }

    const normalizedWebsite = /^https?:\/\//i.test(website.trim()) ? website.trim() : `http://${website.trim()}`;
    const normalizedPortfolio = /^https?:\/\//i.test(portfolio.trim()) ? portfolio.trim() : `http://${portfolio.trim()}`;

    const sub = {
      id: "u" + Date.now(),
      name: fullName,
      email,
      company,
      website: normalizedWebsite,
      portfolio: normalizedPortfolio,
      message,
      ts: Date.now()
    };
    saveUserSubmission(sub);
    setIsSubmitted(true);
  };

  const resetForm = () => {
    setFullName("");
    setEmail("");
    setCompany("");
    setWebsite("");
    setPortfolio("");
    setMessage("");
    setWebsiteStatus(null);
    setWebsiteMsg("");
    setPortfolioStatus(null);
    setPortfolioMsg("");
    setIsSubmitted(false);
  };

  return (
    <div className="min-h-screen relative flex flex-col">
      {/* Background decorations */}
      <div className="bg-decorations" aria-hidden="true">
        <div className="decor-blob blob-1"></div>
        <div className="decor-blob blob-2"></div>
        <div className="decor-circle circle-1"></div>
        <div className="decor-circle circle-2"></div>
        <div className="decor-shape shape-square"></div>
        <div className="decor-shape shape-triangle"></div>
        <div className="decor-shape shape-dashed-circle"></div>
        <div className="decor-shape shape-grid-patch"></div>
        <div className="shape-cross cross-1"></div>
        <div className="shape-cross cross-2"></div>
      </div>

      <div className="container mx-auto px-4 sm:px-6 flex-1 flex flex-col">
        {/* Top Nav */}
        <header className="flex justify-between items-center py-3.5 px-3 sm:px-5 border border-border/50 bg-card/85 backdrop-blur-md rounded-2xl shadow-sm mt-4 mb-6">
          <Link href="/" className="text-base sm:text-lg md:text-xl font-extrabold tracking-tight text-primary flex items-center gap-1.5 sm:gap-2 select-none hover:opacity-90 transition-opacity whitespace-nowrap">
            <ShieldCheck size={20} className="text-primary shrink-0" />
            <span>PhishGuard</span>
          </Link>
          <Link href="/" className={cn(buttonVariants({ variant: "outline" }), "rounded-full gap-1.5 sm:gap-2 border-primary/15 bg-primary/5 hover:bg-primary text-primary hover:text-white transition-all shadow-sm text-xs sm:text-sm h-9 px-3 sm:px-4 shrink-0")}>
            <ArrowLeft size={14} />
            <span className="hidden sm:inline">Dashboard</span>
          </Link>
        </header>

        {/* Hero Banner */}
        <div className="text-center py-9 px-4 max-w-[620px] mx-auto select-none">
          <span className="text-[10px] font-black tracking-widest text-primary uppercase bg-primary/10 border border-primary/15 px-3 py-1 rounded-full mb-3.5 inline-block animate-pulse">
            Form Shield Active
          </span>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight bg-gradient-to-r from-primary via-emerald-800 to-emerald-600 bg-clip-text text-transparent leading-tight mb-3">
            Protected Submission Portal
          </h1>
          <p className="text-xs sm:text-sm text-slate-500/90 max-w-[490px] mx-auto leading-relaxed">
            This form integrates PhishGuard real-time verification to filter out phishing attempts and protect reviewers from malicious URL payloads.
          </p>
        </div>

        {/* Centered protected form panel */}
        <div className="max-w-[840px] mx-auto w-full px-2 sm:px-4 pb-16">
          {!isSubmitted ? (
            <Card className={`border border-border/60 shadow-xl p-5 sm:p-8 rounded-3xl bg-white/95 backdrop-blur-md transition-all duration-300 ${shakeForm ? "shake" : ""}`}>
              <div className="flex items-center gap-3.5 pb-4 border-b border-border/60 mb-6">
                <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary to-emerald-600 text-white font-black flex items-center justify-center text-base shadow-lg shadow-primary/10 border border-primary/20 select-none">
                  TC
                </div>
                <div>
                  <h2 className="text-sm sm:text-base font-bold text-slate-900">TechCorp Partnerships</h2>
                  <p className="text-[11px] sm:text-xs text-muted-foreground font-medium">Vendor application form. All web addresses are scanned instantly.</p>
                </div>
              </div>

              <div className="flex flex-col gap-4">
                {/* Row 1: Full Name and Email */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="flex flex-col gap-1.5">
                    <label className="text-[11px] font-bold text-slate-500 uppercase tracking-wide">Full Name *</label>
                    <Input
                      type="text"
                      required
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      placeholder="Jane Smith"
                      className="h-10 rounded-xl bg-slate-50/50 hover:bg-slate-50/80 focus:bg-white transition-all border border-border/80 text-xs sm:text-sm px-4 focus-visible:ring-primary/20 focus-visible:border-primary shadow-inner"
                    />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <label className="text-[11px] font-bold text-slate-500 uppercase tracking-wide">Email Address *</label>
                    <Input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="jane@company.com"
                      className="h-10 rounded-xl bg-slate-50/50 hover:bg-slate-50/80 focus:bg-white transition-all border border-border/80 text-xs sm:text-sm px-4 focus-visible:ring-primary/20 focus-visible:border-primary shadow-inner"
                    />
                  </div>
                </div>

                {/* Row 2: Company Name */}
                <div className="flex flex-col gap-1.5">
                  <label className="text-[11px] font-bold text-slate-500 uppercase tracking-wide">Company Name</label>
                  <Input
                    type="text"
                    value={company}
                    onChange={(e) => setCompany(e.target.value)}
                    placeholder="Acme Corp"
                    className="h-10 rounded-xl bg-slate-50/50 hover:bg-slate-50/80 focus:bg-white transition-all border border-border/80 text-xs sm:text-sm px-4 focus-visible:ring-primary/20 focus-visible:border-primary shadow-inner"
                  />
                </div>

                {/* Row 3: Website URL */}
                <div className="flex flex-col gap-1.5">
                  <label className="text-[11px] font-bold text-slate-500 uppercase tracking-wide">Company Website *</label>
                  <div className="relative">
                    <Input
                      type="text"
                      required
                      value={website}
                      onChange={(e) => setWebsite(e.target.value)}
                      placeholder="https://company.com"
                      className={`h-10 rounded-xl pr-9 bg-slate-50/50 hover:bg-slate-50/80 focus:bg-white transition-all border border-border/80 text-xs sm:text-sm px-4 shadow-inner ${
                        websiteStatus === "unsafe" ? "border-red-500 focus-visible:ring-red-500 focus-visible:border-red-500" :
                        websiteStatus === "safe" ? "border-emerald-500 focus-visible:ring-emerald-500 focus-visible:border-emerald-500" : "focus-visible:ring-primary/20 focus-visible:border-primary"
                      }`}
                    />
                    <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center">
                      {websiteStatus === "checking" && <Loader2 className="animate-spin text-primary" size={16} />}
                      {websiteStatus === "safe" && <CheckCircle2 className="text-emerald-500" size={16} />}
                      {websiteStatus === "unsafe" && <AlertTriangle className="text-red-500" size={16} />}
                    </div>
                  </div>
                  {websiteMsg && (
                    <div className={`text-[11px] font-semibold flex items-center gap-1.5 p-2 rounded-lg border ${
                      websiteStatus === "unsafe" ? "text-red-600 bg-red-50/50 border-red-100 animate-in fade-in" : "text-slate-500 bg-slate-50/50 border-slate-100 animate-in fade-in"
                    }`}>
                      {websiteStatus === "unsafe" ? <AlertTriangle size={13} /> : <Loader2 size={13} className="animate-spin" />}
                      <span>{websiteMsg}</span>
                    </div>
                  )}
                </div>

                {/* Row 4: Portfolio URL */}
                <div className="flex flex-col gap-1.5">
                  <label className="text-[11px] font-bold text-slate-500 uppercase tracking-wide">Portfolio / Reference URL *</label>
                  <div className="relative">
                    <Input
                      type="text"
                      required
                      value={portfolio}
                      onChange={(e) => setPortfolio(e.target.value)}
                      placeholder="https://portfolio.example.com"
                      className={`h-10 rounded-xl pr-9 bg-slate-50/50 hover:bg-slate-50/80 focus:bg-white transition-all border border-border/80 text-xs sm:text-sm px-4 shadow-inner ${
                        portfolioStatus === "unsafe" ? "border-red-500 focus-visible:ring-red-500 focus-visible:border-red-500" :
                        portfolioStatus === "safe" ? "border-emerald-500 focus-visible:ring-emerald-500 focus-visible:border-emerald-500" : "focus-visible:ring-primary/20 focus-visible:border-primary"
                      }`}
                    />
                    <div className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center">
                      {portfolioStatus === "checking" && <Loader2 className="animate-spin text-primary" size={16} />}
                      {portfolioStatus === "safe" && <CheckCircle2 className="text-emerald-500" size={16} />}
                      {portfolioStatus === "unsafe" && <AlertTriangle className="text-red-500" size={16} />}
                    </div>
                  </div>
                  {portfolioMsg && (
                    <div className={`text-[11px] font-semibold flex items-center gap-1.5 p-2 rounded-lg border ${
                      portfolioStatus === "unsafe" ? "text-red-600 bg-red-50/50 border-red-100 animate-in fade-in" : "text-slate-500 bg-slate-50/50 border-slate-100 animate-in fade-in"
                    }`}>
                      {portfolioStatus === "unsafe" ? <AlertTriangle size={13} /> : <Loader2 size={13} className="animate-spin" />}
                      <span>{portfolioMsg}</span>
                    </div>
                  )}
                </div>

                {/* Row 5: Message */}
                <div className="flex flex-col gap-1.5">
                  <label className="text-[11px] font-bold text-slate-500 uppercase tracking-wide">Partnership Message</label>
                  <Textarea
                    value={message}
                    onChange={(e) => setMessage(e.target.value)}
                    placeholder="Tell us about your product or partnership interest..."
                    className="min-h-[110px] rounded-xl py-2.5 px-4 resize-none bg-slate-50/50 hover:bg-slate-50/80 focus:bg-white transition-all border border-border/80 text-xs sm:text-sm focus-visible:ring-primary/20 focus-visible:border-primary shadow-inner"
                  />
                </div>

                {/* Alert message for blocked submission */}
                {isSubmitBlocked && (fullName || email || website || portfolio) && (
                  <div className="flex items-center gap-2 p-3 text-xs font-semibold text-red-600 border border-red-100 bg-red-50/40 rounded-xl mt-1.5">
                    <AlertTriangle size={15} />
                    <span>Submission blocked — fill up all required fields and correct any flagged links.</span>
                  </div>
                )}

                {/* Card footer block */}
                <div className="flex flex-col-reverse sm:flex-row justify-between items-center gap-4 mt-3 pt-3 border-t border-border/60 bg-muted/10 -mx-5 sm:-mx-8 px-5 sm:px-8 -mb-5 sm:-mb-8 rounded-b-3xl py-3.5">
                  <div className="flex items-center gap-1.5 text-xs font-bold text-slate-400 select-none">
                    <ShieldCheck size={16} className="text-primary/70" />
                    <span>Protected by PhishGuard Form Shield</span>
                  </div>
                  <Button
                    onClick={handleFormSubmit}
                    disabled={isSubmitBlocked}
                    className="w-full sm:w-auto h-11 px-7 rounded-xl font-extrabold bg-primary hover:bg-primary/95 text-white transition-all hover:scale-[1.01] hover:shadow-md active:scale-95 disabled:pointer-events-none disabled:opacity-50 text-xs sm:text-sm shadow-sm"
                  >
                    Submit Application
                  </Button>
                </div>
              </div>
            </Card>
          ) : (
            /* Success state card */
            <Card className="border-emerald-100 shadow-premium p-8 rounded-2xl bg-white/95 backdrop-blur-sm flex flex-col items-center text-center animate-in fade-in slide-in-from-bottom-2 duration-300">
              <div className="w-16 h-16 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center mb-4 shadow-inner">
                <CheckCircle2 size={32} />
              </div>
              <h3 className="text-lg font-bold text-slate-900">Application Submitted!</h3>
              <p className="text-xs sm:text-sm text-slate-500 mt-2 max-w-[340px]">
                Thank you for your submission. Your credentials and links were verified safe and saved successfully.
              </p>
              <div className="flex gap-3 mt-6">
                <Button variant="outline" className="rounded-xl h-10 px-5 font-bold border-slate-200 text-slate-700 hover:bg-slate-50 text-xs sm:text-sm shadow-sm" onClick={resetForm}>
                  Submit Another
                </Button>
                <Link href="/" className={cn(buttonVariants({ variant: "default" }), "rounded-xl h-10 px-5 font-bold bg-primary hover:bg-primary/95 text-white text-xs sm:text-sm shadow-sm flex items-center justify-center")}>
                  Go to Dashboard
                </Link>
              </div>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
