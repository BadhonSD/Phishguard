"use client";

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import jsQR from "jsqr";
import { 
  ShieldCheck, 
  Shield, 
  Link2, 
  QrCode, 
  History, 
  CheckCircle2, 
  AlertTriangle, 
  ExternalLink,
  Loader2,
  Download
} from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button, buttonVariants } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import { getHistory, addHistoryEntry, HistoryEntry } from "@/lib/db";
import PWAInstallPrompt from "@/components/PWAInstallPrompt";

// FastAPI backend base URL
const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const RISK_THRESHOLDS = { green: 0.3, yellow: 0.6 };

function riskLevel(confidence: number) {
  if (confidence < RISK_THRESHOLDS.green) return "green";
  if (confidence < RISK_THRESHOLDS.yellow) return "yellow";
  return "red";
}

function riskLabel(level: "green" | "yellow" | "red") {
  return { green: "Looks Safe", yellow: "Use Caution", red: "Likely Phishing" }[level];
}

interface FeatureContribution {
  feature: string;
  value: number;
  importance: number;
}

interface URLCheckResponse {
  url: string;
  is_phishing: boolean;
  confidence: number;
  top_features: FeatureContribution[];
}

export default function Home() {
  const [activeTab, setActiveTab] = useState<"check" | "scan">("check");

  // PWA Install Prompt state
  const [showInstallBtn, setShowInstallBtn] = useState(false);

  useEffect(() => {
    const isStandalone = 
      window.matchMedia("(display-mode: standalone)").matches || 
      (window.navigator as any).standalone === true;
    setShowInstallBtn(!isStandalone);
  }, []);

  const triggerInstallPrompt = () => {
    localStorage.removeItem("pwa-prompt-dismissed");
    window.dispatchEvent(new Event("show-pwa-prompt"));
  };

  // Manual URL Check State
  const [urlInput, setUrlInput] = useState("");
  const [isChecking, setIsChecking] = useState(false);
  const [checkError, setCheckError] = useState<string | null>(null);
  const [checkResult, setCheckResult] = useState<URLCheckResponse | null>(null);

  // History State
  const [historyEntries, setHistoryEntries] = useState<HistoryEntry[]>([]);

  // QR Scanner State
  const [scanStatus, setScanStatus] = useState("Point your camera at a QR code");
  const [isScanning, setIsScanning] = useState(false);
  const [showScanAgain, setShowScanAgain] = useState(false);

  // Overlays State
  const [overlayData, setOverlayData] = useState<URLCheckResponse | null>(null);
  const [overlayType, setOverlayType] = useState<"safe" | "danger" | null>(null);
  const [revealDangerLink, setRevealDangerLink] = useState(false);

  // Refs for Scanner
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const rafRef = useRef<number | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  // Load history on mount or state change
  const loadHistory = async () => {
    const entries = await getHistory();
    setHistoryEntries(entries);
  };

  // Handle Tab Switch camera lifecycle
  useEffect(() => {
    if (activeTab === "scan") {
      startScanner();
    } else {
      stopScanner();
    }
    return () => {
      stopScanner();
    };
  }, [activeTab]);

  // API Client Call
  async function checkUrlApi(url: string): Promise<URLCheckResponse> {
    const resp = await fetch(`${API_BASE_URL}/api/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (!resp.ok) {
      let detail = `Request failed (${resp.status})`;
      try {
        const body = await resp.json();
        detail = body.detail ? (Array.isArray(body.detail) ? body.detail[0].msg : body.detail) : detail;
      } catch (_) {}
      throw new Error(detail);
    }
    return resp.json();
  }

  // Handle Manual Form Check Submit
  const handleCheckSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const url = urlInput.trim();
    if (!url) return;

    setCheckError(null);
    setCheckResult(null);
    setIsChecking(true);

    try {
      const data = await checkUrlApi(url);
      setCheckResult(data);
      await addHistoryEntry({
        url: data.url,
        isPhishing: data.is_phishing,
        confidence: data.confidence,
        source: "manual",
      });
      await loadHistory(); // Refresh history background
    } catch (err: any) {
      setCheckError(err.message || "An unexpected error occurred");
    } finally {
      setIsChecking(false);
    }
  };

  // QR Scanner Implementation
  const startScanner = async () => {
    setShowScanAgain(false);
    hideOverlays();

    if (isScanning) return;

    // Prompt for media stream if we don't already have one
    if (!streamRef.current) {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: "environment" },
        });
        streamRef.current = stream;
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
        }
      } catch (err) {
        setScanStatus("Camera access denied or unavailable.");
        return;
      }
    }

    if (videoRef.current) {
      try {
        await videoRef.current.play();
        setIsScanning(true);
        setScanStatus("Point your camera at a QR code");
        rafRef.current = requestAnimationFrame(qrTick);
      } catch (e) {
        console.error("Video play failed:", e);
      }
    }
  };

  const stopScanner = () => {
    setIsScanning(false);
    if (rafRef.current) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((track) => track.stop());
      streamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
  };

  const freezeScanner = () => {
    setIsScanning(false);
    if (rafRef.current) {
      cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.pause();
    }
  };

  const qrTick = () => {
    const video = videoRef.current;
    if (!video || video.paused || video.ended) {
      rafRef.current = requestAnimationFrame(qrTick);
      return;
    }

    if (video.readyState === video.HAVE_ENOUGH_DATA) {
      if (!canvasRef.current) {
        canvasRef.current = document.createElement("canvas");
      }
      const canvas = canvasRef.current;
      const ctx = canvas.getContext("2d", { willReadFrequently: true });

      if (ctx) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, imageData.width, imageData.height);
        if (code && code.data) {
          handleDecodedValue(code.data);
          return; // pause loop
        }
      }
    }
    rafRef.current = requestAnimationFrame(qrTick);
  };

  const looksLikeUrl = (text: string) => {
    return /^https?:\/\//i.test(text) || /^[\w-]+(\.[\w-]+)+(\/.*)?$/i.test(text);
  };

  const handleDecodedValue = async (text: string) => {
    freezeScanner();
    setShowScanAgain(true);

    if (!looksLikeUrl(text)) {
      setScanStatus(`Scanned content is not a URL: "${text}"`);
      return;
    }

    setScanStatus("Checking URL…");
    try {
      const data = await checkUrlApi(text);
      await addHistoryEntry({
        url: data.url,
        isPhishing: data.is_phishing,
        confidence: data.confidence,
        source: "qr",
      });
      await loadHistory(); // Refresh history background
      showResultOverlay(data);
      setScanStatus("Point your camera at a QR code");
    } catch (err: any) {
      setScanStatus(`Error checking URL: ${err.message}`);
    }
  };

  // Overlays
  const showResultOverlay = (data: URLCheckResponse) => {
    setOverlayData(data);
    setOverlayType(data.is_phishing ? "danger" : "safe");
    setRevealDangerLink(false);
  };

  const hideOverlays = () => {
    setOverlayType(null);
    setOverlayData(null);
    setRevealDangerLink(false);
  };

  const resumeScanning = () => {
    hideOverlays();
    setShowScanAgain(false);
    startScanner();
  };

  // Trigger initial history loading
  useEffect(() => {
    loadHistory();
  }, []);

  return (
    <div className="min-h-screen relative flex flex-col">
      <PWAInstallPrompt />
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
        <header className="flex justify-between items-center py-3.5 px-3 sm:px-5 border border-border/50 bg-card/85 backdrop-blur-md rounded-2xl shadow-sm mt-4 mb-6">
          <Link href="/" className="text-base sm:text-lg md:text-xl font-extrabold tracking-tight text-primary flex items-center gap-1.5 sm:gap-2 select-none hover:opacity-90 transition-opacity whitespace-nowrap">
            <ShieldCheck size={20} className="text-primary shrink-0" />
            <span>PhishGuard</span>
          </Link>
          <div className="flex items-center gap-1 sm:gap-2.5">
            {showInstallBtn && (
              <Button 
                onClick={triggerInstallPrompt}
                variant="ghost" 
                className="rounded-full gap-1.5 text-xs h-9 px-2.5 sm:px-3 text-muted-foreground hover:text-primary hover:bg-primary/5 border border-transparent hover:border-primary/10 transition-all font-bold shrink-0"
              >
                <Download size={13} />
                <span className="hidden sm:inline">Install App</span>
              </Button>
            )}
            <Link href="/formshield" className={cn(buttonVariants({ variant: "outline" }), "rounded-full gap-1.5 sm:gap-2 border-primary/15 bg-primary/5 hover:bg-primary text-primary hover:text-white transition-all shadow-sm text-xs sm:text-sm h-9 px-3 sm:px-4 shrink-0")}>
              <Shield size={14} />
              <span className="hidden sm:inline">Form Shield</span>
            </Link>
          </div>
        </header>

        {/* Dashboard Grid Container */}
        <div className="grid grid-cols-1 lg:grid-cols-[1.6fr_1fr] gap-6 lg:gap-8 items-start py-2 sm:py-4 flex-1">
          {/* Main Workspace (Left side on Desktop) */}
          <div className="flex flex-col gap-4 sm:gap-6">
            
            {/* View Switcher Grid */}
            <div className="grid grid-cols-2 gap-3 sm:gap-4">
              <Card 
                className={`flex flex-col items-center justify-center text-center gap-3 p-4 sm:p-5 cursor-pointer transition-all border border-border/50 hover:translate-y-[-1px] hover:border-primary/20 hover:shadow-md rounded-2xl ${activeTab === "check" ? "border-primary bg-primary/2 shadow-sm" : ""}`}
                onClick={() => setActiveTab("check")}
              >
                <div className={`w-8.5 h-8.5 sm:w-9.5 sm:h-9.5 rounded-xl flex items-center justify-center transition-all ${activeTab === "check" ? "bg-primary text-white shadow-sm" : "bg-primary/5 text-primary"}`}>
                  <Link2 size={18} />
                </div>
                <div className="flex flex-col items-center text-center">
                  <span className={`text-xs sm:text-sm font-bold transition-colors ${activeTab === "check" ? "text-primary" : "text-foreground"}`}>Link Guard</span>
                  <span className="text-[10px] sm:text-[11px] text-muted-foreground font-medium hidden sm:inline">Verify links in real-time</span>
                </div>
              </Card>

              <Card 
                className={`flex flex-col items-center justify-center text-center gap-3 p-4 sm:p-5 cursor-pointer transition-all border border-border/50 hover:translate-y-[-1px] hover:border-primary/20 hover:shadow-md rounded-2xl ${activeTab === "scan" ? "border-primary bg-primary/2 shadow-sm" : ""}`}
                onClick={() => setActiveTab("scan")}
              >
                <div className={`w-8.5 h-8.5 sm:w-9.5 sm:h-9.5 rounded-xl flex items-center justify-center transition-all ${activeTab === "scan" ? "bg-primary text-white shadow-sm" : "bg-primary/5 text-primary"}`}>
                  <QrCode size={18} />
                </div>
                <div className="flex flex-col items-center text-center">
                  <span className={`text-xs sm:text-sm font-bold transition-colors ${activeTab === "scan" ? "text-primary" : "text-foreground"}`}>QR Guard</span>
                  <span className="text-[10px] sm:text-[11px] text-muted-foreground font-medium hidden sm:inline">Scan & inspect QR codes</span>
                </div>
              </Card>
            </div>

            {/* Panel Check URL */}
            <Card className={`${activeTab === "check" ? "block" : "hidden"} border-border/50 shadow-md p-4 sm:p-6 rounded-2xl bg-card/95 backdrop-blur-sm`}>
              <CardHeader className="p-0 mb-4 sm:mb-5">
                <CardTitle className="text-base sm:text-lg font-bold flex items-center gap-2">
                  <Link2 size={18} className="text-primary" />
                  <span>Real-Time URL Verification</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <form className="flex flex-col sm:flex-row gap-2.5 mb-4" onSubmit={handleCheckSubmit}>
                  <div className="relative flex-1">
                    <Input
                      type="text"
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      placeholder="Enter URL to analyze (e.g. https://google.com)"
                      autoComplete="off"
                      autoCapitalize="off"
                      className="w-full h-10 sm:h-11 px-3 sm:px-4 rounded-xl border border-input bg-card focus-visible:ring-primary focus-visible:border-primary text-xs sm:text-sm font-medium shadow-inner"
                    />
                  </div>
                  <Button type="submit" className="h-10 sm:h-11 px-5 sm:px-6 rounded-xl font-bold bg-primary hover:bg-primary/95 text-white transition-all shadow-sm text-xs sm:text-sm w-full sm:w-auto" disabled={isChecking}>
                    {isChecking ? (
                      <>
                        <Loader2 className="animate-spin mr-2" size={14} />
                        <span>Analyzing…</span>
                      </>
                    ) : (
                      "Verify"
                    )}
                  </Button>
                </form>
                
                {checkError && (
                  <div className="flex items-center gap-2 text-xs font-semibold text-red-600 mt-2 p-3 rounded-lg border border-red-100 bg-red-50/50">
                    <AlertTriangle size={15} />
                    <span>{checkError}</span>
                  </div>
                )}
                
                {checkResult && (
                  <div className="mt-4 p-3 sm:p-4 rounded-xl border border-border bg-muted/20 animate-in fade-in slide-in-from-bottom-2 duration-300">
                    <div className="flex items-center mb-2.5">
                      <Badge className={`h-5.5 gap-1 px-2 text-[10px] font-bold rounded-full border shadow-none ${riskLevel(checkResult.confidence) === "green" ? "bg-emerald-50 text-emerald-700 border-emerald-100 hover:bg-emerald-50" : riskLevel(checkResult.confidence) === "yellow" ? "bg-amber-50 text-amber-700 border-amber-100 hover:bg-amber-50" : "bg-red-50 text-red-700 border-red-100 hover:bg-red-50"}`}>
                        {riskLevel(checkResult.confidence) === "green" ? (
                          <CheckCircle2 size={10} />
                        ) : (
                          <AlertTriangle size={10} />
                        )}
                        <span>{riskLabel(riskLevel(checkResult.confidence))} · {Math.round(checkResult.confidence * 100)}%</span>
                      </Badge>
                    </div>
                    
                    <div className="text-xs sm:text-sm font-mono font-medium text-slate-700 break-all bg-white/50 p-2.5 rounded-lg border border-border/40">{checkResult.url}</div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Panel Scan QR */}
            <Card className={`${activeTab === "scan" ? "block" : "hidden"} border-border/50 shadow-md p-4 sm:p-6 rounded-2xl bg-card/95 backdrop-blur-sm`}>
              <CardHeader className="p-0 mb-4 sm:mb-5">
                <CardTitle className="text-base sm:text-lg font-bold flex items-center gap-2">
                  <QrCode size={18} className="text-primary" />
                  <span>Scan QR Code Link</span>
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0 flex flex-col items-center">
                <div className="scanner-wrap max-w-[290px] sm:max-w-[380px]">
                  <video ref={videoRef} playsInline muted></video>
                  <div className="scanner-frame"></div>
                </div>
                <p className="text-xs font-medium text-slate-500 mt-3 text-center">{scanStatus}</p>
                
                {showScanAgain && (
                  <Button className="mt-4 bg-primary hover:bg-primary/95 text-white rounded-xl h-10 px-5 font-bold shadow-sm" onClick={resumeScanning}>
                    Scan Again
                  </Button>
                )}
              </CardContent>
            </Card>
            
          </div>

          {/* Persistent Sidebar on Desktop and stacked below on mobile */}
          <Card className="border-border/50 shadow-md p-4 sm:p-6 rounded-2xl bg-card/95 backdrop-blur-sm">
            <CardHeader className="p-0 mb-4 sm:mb-5">
              <CardTitle className="text-base sm:text-lg font-bold flex items-center gap-2">
                <History size={18} className="text-primary" />
                <span>Recent Checks</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <ul className="history-list flex flex-col gap-2 max-h-[400px] lg:max-h-[calc(100vh-270px)] lg:min-h-[250px] overflow-y-auto pr-1">
                {historyEntries.length === 0 ? (
                  <div className="text-center text-xs font-medium text-muted-foreground py-8 italic">No scans logged yet.</div>
                ) : (
                  historyEntries.map((entry, idx) => {
                    const level = riskLevel(entry.confidence);
                    const pct = Math.round(entry.confidence * 100);
                    const when = new Date(entry.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    return (
                      <li className="p-3 rounded-xl border border-border/60 hover:border-primary/20 bg-card hover:shadow-sm transition-all flex flex-col gap-2" key={idx}>
                        <div className="flex justify-between items-center">
                          <Badge className={`h-5 gap-1.5 px-2 text-[10px] font-bold rounded-full border shadow-none ${level === "green" ? "bg-emerald-50 text-emerald-700 border-emerald-100 hover:bg-emerald-50" : level === "yellow" ? "bg-amber-50 text-amber-700 border-amber-100 hover:bg-amber-50" : "bg-red-50 text-red-700 border-red-100 hover:bg-red-50"}`}>
                            {level === "green" ? (
                              <CheckCircle2 size={10} />
                            ) : (
                              <AlertTriangle size={10} />
                            )}
                            <span>{riskLabel(level)} · {pct}%</span>
                          </Badge>
                          
                          <span className="text-[10px] font-bold text-muted-foreground flex items-center gap-1">
                            {entry.source === "qr" ? (
                              <QrCode size={11} />
                            ) : (
                              <Link2 size={11} />
                            )}
                            <span>{when}</span>
                          </span>
                        </div>
                        <div className="text-xs font-mono font-medium text-slate-600 break-all">{entry.url}</div>
                      </li>
                    );
                  })
                )}
              </ul>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Warning backdrop modal */}
      <Dialog open={overlayType === "danger"} onOpenChange={(open) => !open && hideOverlays()}>
        <DialogContent className="max-w-[360px] sm:max-w-[420px] p-5 sm:p-6 rounded-2xl border-red-100 bg-white/95 backdrop-blur-md shadow-2xl flex flex-col items-center text-center">
          <div className="w-14 h-14 sm:w-16 sm:h-16 rounded-full bg-red-50 text-red-600 flex items-center justify-center mb-2 shadow-inner">
            <AlertTriangle size={30} />
          </div>
          <h2 className="text-base sm:text-lg font-bold text-slate-900">Warning: Likely Phishing</h2>
          <p className="text-xs sm:text-sm font-semibold text-red-600 mt-0.5">{overlayData ? Math.round(overlayData.confidence * 100) : 0}% confidence score</p>
          <div className="w-full text-xs font-mono p-3 bg-slate-50 border border-slate-200 rounded-xl break-all my-3.5 text-slate-600 font-medium">{overlayData?.url}</div>
          <div className="flex flex-col gap-2 w-full">
            {!revealDangerLink ? (
              <Button variant="outline" className="w-full border-slate-200 text-slate-700 hover:bg-slate-50 rounded-xl h-10 font-bold text-xs" onClick={() => setRevealDangerLink(true)}>
                I understand the risk, show me anyway
              </Button>
            ) : (
              <a 
                href={overlayData?.url} 
                target="_blank" 
                rel="noopener noreferrer" 
                className={cn(buttonVariants({ variant: "destructive" }), "w-full h-10 font-bold text-xs rounded-xl shadow-sm gap-1 flex justify-center items-center")}
              >
                <span>Open Anyway</span>
                <ExternalLink size={13} />
              </a>
            )}
            <Button className="w-full h-10 font-bold bg-primary hover:bg-primary/95 text-white rounded-xl text-xs shadow-sm" onClick={resumeScanning}>
              Scan Again
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Safe backdrop modal */}
      <Dialog open={overlayType === "safe"} onOpenChange={(open) => !open && hideOverlays()}>
        <DialogContent className="max-w-[360px] sm:max-w-[420px] p-5 sm:p-6 rounded-2xl border-emerald-100 bg-white/95 backdrop-blur-md shadow-2xl flex flex-col items-center text-center">
          <div className="w-14 h-14 sm:w-16 sm:h-16 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center mb-2 shadow-inner">
            <CheckCircle2 size={30} />
          </div>
          <h2 className="text-base sm:text-lg font-bold text-slate-900">URL Verified Safe</h2>
          <p className="text-xs sm:text-sm font-semibold text-emerald-600 mt-0.5">{overlayData ? Math.round((1 - overlayData.confidence) * 100) : 0}% safety score</p>
          <div className="w-full text-xs font-mono p-3 bg-slate-50 border border-slate-200 rounded-xl break-all my-3.5 text-slate-600 font-medium">{overlayData?.url}</div>
          <div className="flex flex-col gap-2 w-full">
            <a 
              href={overlayData?.url} 
              target="_blank" 
              rel="noopener noreferrer" 
              className={cn(buttonVariants({ variant: "default" }), "w-full h-10 font-bold bg-emerald-600 hover:bg-emerald-700 text-white rounded-xl text-xs shadow-sm gap-1 flex justify-center items-center")}
            >
              <span>Open Link</span>
              <ExternalLink size={13} />
            </a>
            <Button variant="outline" className="w-full h-10 font-bold border-slate-200 text-slate-700 hover:bg-slate-50 rounded-xl text-xs shadow-sm" onClick={resumeScanning}>
              Scan Again
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
