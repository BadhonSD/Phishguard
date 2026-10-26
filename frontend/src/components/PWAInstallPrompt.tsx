"use client";

import { useState, useEffect, useRef } from "react";
import { X, Download, ShieldCheck, Share, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export default function PWAInstallPrompt() {
  const [isVisible, setIsVisible] = useState(false);
  const [isIOS, setIsIOS] = useState(false);
  const [deferredPrompt, setDeferredPrompt] = useState<any>(null);

  useEffect(() => {
    // 1. Check if already installed / running in standalone mode
    const isStandalone = 
      window.matchMedia("(display-mode: standalone)").matches || 
      (window.navigator as any).standalone === true;

    if (isStandalone) {
      return; // Already installed, do not show
    }

    // 2. Check if user previously dismissed the prompt in this session
    const isDismissed = localStorage.getItem("pwa-prompt-dismissed") === "true";
    if (isDismissed) {
      return;
    }

    // 3. Detect iOS device
    const userAgent = window.navigator.userAgent.toLowerCase();
    const detectIOS = /iphone|ipad|ipod/.test(userAgent);
    setIsIOS(detectIOS);

    // 4. Handle Android / Chrome beforeinstallprompt event
    const handleBeforeInstallPrompt = (e: Event) => {
      e.preventDefault();
      setDeferredPrompt(e);
      // Show prompt after a short delay once home page loads
      const timer = setTimeout(() => {
        setIsVisible(true);
      }, 1500);
      return () => clearTimeout(timer);
    };

    window.addEventListener("beforeinstallprompt", handleBeforeInstallPrompt);

    const handleShowPrompt = () => {
      setIsVisible(true);
    };
    window.addEventListener("show-pwa-prompt", handleShowPrompt);

    // 5. For iOS, we can display the instruction banner after home page load
    if (detectIOS) {
      const timer = setTimeout(() => {
        setIsVisible(true);
      }, 2000);
      return () => {
        clearTimeout(timer);
        window.removeEventListener("beforeinstallprompt", handleBeforeInstallPrompt);
        window.removeEventListener("show-pwa-prompt", handleShowPrompt);
      };
    }

    return () => {
      window.removeEventListener("beforeinstallprompt", handleBeforeInstallPrompt);
      window.removeEventListener("show-pwa-prompt", handleShowPrompt);
    };
  }, []);

  const handleInstallClick = async () => {
    if (!deferredPrompt) return;

    deferredPrompt.prompt();

    const { outcome } = await deferredPrompt.userChoice;
    console.log(`User response to the install prompt: ${outcome}`);

    setDeferredPrompt(null);
    setIsVisible(false);
  };

  const handleDismiss = () => {
    localStorage.setItem("pwa-prompt-dismissed", "true");
    setIsVisible(false);
  };

  if (!isVisible) return null;

  return (
    <div className="fixed bottom-4 left-4 right-4 md:left-auto md:right-6 md:bottom-6 z-[100] md:max-w-sm animate-in slide-in-from-bottom-5 fade-in duration-300">
      <div className="bg-card/95 dark:bg-slate-900/95 backdrop-blur-md border border-primary/15 shadow-2xl rounded-3xl p-5 relative overflow-hidden">
        {/* Decorative background gradient */}
        <div className="absolute top-0 right-0 w-24 h-24 bg-primary/5 rounded-full blur-xl pointer-events-none"></div>

        {/* Close Button */}
        <button 
          onClick={handleDismiss} 
          className="absolute top-3.5 right-3.5 text-muted-foreground hover:text-foreground hover:bg-muted/50 p-1.5 rounded-full transition-colors"
          aria-label="Close install prompt"
        >
          <X size={15} />
        </button>

        <div className="flex gap-4 items-start pr-4">
          <div className="w-10 h-10 rounded-xl bg-primary/10 text-primary flex items-center justify-center shrink-0 shadow-inner">
            <ShieldCheck size={22} />
          </div>
          <div className="flex-1">
            <h3 className="text-sm font-extrabold text-foreground tracking-tight mb-1">
              Install PhishGuard App
            </h3>
            <p className="text-xs text-muted-foreground leading-normal mb-3">
              Add PhishGuard to your home screen for instant AI link checks and protected submissions.
            </p>
          </div>
        </div>

        {isIOS ? (
          /* iOS Safari installation instructions */
          <div className="border-t border-border/60 pt-3 mt-1 flex flex-col gap-2.5">
            <p className="text-[10px] font-bold uppercase tracking-wider text-primary">Instructions for iOS</p>
            <ol className="text-xs text-muted-foreground flex flex-col gap-2 pl-1 select-none font-medium">
              <li className="flex items-center gap-2">
                <span className="w-4.5 h-4.5 rounded-full bg-primary/5 border border-primary/15 flex items-center justify-center text-[10px] font-black text-primary">1</span>
                <span>Tap the share button <Share size={12} className="inline mx-1 text-primary" /> in Safari.</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="w-4.5 h-4.5 rounded-full bg-primary/5 border border-primary/15 flex items-center justify-center text-[10px] font-black text-primary">2</span>
                <span>Scroll down and select <strong>Add to Home Screen</strong> <Plus size={12} className="inline mx-1 text-primary" />.</span>
              </li>
              <li className="flex items-center gap-2">
                <span className="w-4.5 h-4.5 rounded-full bg-primary/5 border border-primary/15 flex items-center justify-center text-[10px] font-black text-primary">3</span>
                <span>Tap <strong>Add</strong> at the top right.</span>
              </li>
            </ol>
            <div className="flex justify-end gap-2 border-t border-border/40 pt-3 mt-1">
              <Button 
                variant="ghost" 
                onClick={handleDismiss} 
                className="h-8 text-xs font-bold text-slate-500 hover:text-slate-700 hover:bg-slate-50"
              >
                Got It
              </Button>
            </div>
          </div>
        ) : (
          /* Android / Chrome Desktop direct installation */
          <div className="flex gap-2 justify-end border-t border-border/40 pt-3 mt-1">
            <Button 
              variant="ghost" 
              onClick={handleDismiss} 
              className="h-8.5 text-xs font-bold text-slate-500 hover:text-slate-700 hover:bg-slate-50 rounded-xl"
            >
              Maybe Later
            </Button>
            <Button 
              onClick={handleInstallClick} 
              className="h-8.5 text-xs font-bold bg-primary hover:bg-primary/95 text-white rounded-xl shadow-sm flex items-center gap-1.5 px-4"
              disabled={!deferredPrompt}
            >
              <Download size={12} />
              <span>Install App</span>
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
