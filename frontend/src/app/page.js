"use client";

import { useState, useCallback } from "react";
import { Tabs, TabsContent } from "@/components/ui/tabs";
import { ShieldCheck, ChartBar } from "@phosphor-icons/react";
import Header from "@/components/layout/Header";
import HistorySidebar from "@/components/layout/HistorySidebar";
import ScannerPanel from "@/components/scanner/ScannerPanel";
import AnalyticsPanel from "@/components/analytics/AnalyticsPanel";
import RiskScorecard from "@/components/results/RiskScorecard";
import EducationalModule from "@/components/results/EducationalModule";
import IntelPanel from "@/components/results/IntelPanel";
import { AnimatedTabs, AnimatedButton } from "@/components/ui/AnimatedTabs";

export default function Home() {
  const [activeTab, setActiveTab] = useState("scanner");
  const [refreshKey, setRefreshKey] = useState(0);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selectedScan, setSelectedScan] = useState(null);

  const handleScanComplete = useCallback(() => {
    setRefreshKey((k) => k + 1);
  }, []);

  function handleSelectScan(scan) {
    setSelectedScan(scan);
    setActiveTab("scanner");
  }

  function handleBackToScanner() {
    setSelectedScan(null);
  }

  return (
    <div className="min-h-screen bg-background">
      <Header onMenuClick={() => setSidebarOpen(true)} sidebarOpen={sidebarOpen} />

      <HistorySidebar
        open={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
        onSelectScan={handleSelectScan}
        refreshKey={refreshKey}
      />

      <main className="max-w-2xl mx-auto px-4 py-8">
        <Tabs value={activeTab} onValueChange={(v) => { setActiveTab(v); setSelectedScan(null); }}>
          <div className="mb-6">
            <AnimatedTabs
              value={activeTab}
              onChange={(v) => { setActiveTab(v); setSelectedScan(null); }}
              options={[
                { value: "scanner", label: "Scanner", icon: ShieldCheck },
                { value: "analytics", label: "Analytics", icon: ChartBar },
              ]}
              layoutId="main-tabs"
            />
          </div>

          <TabsContent value="scanner" className="mt-0">
            {selectedScan ? (
              <div className="space-y-4">
                <RiskScorecard result={selectedScan} />
                {selectedScan.intel && <IntelPanel intel={selectedScan.intel} />}
                <EducationalModule education={selectedScan.education} label={selectedScan.label} />
                <div className="h-24" />
                <AnimatedButton
                  onClick={handleBackToScanner}
                  className="fixed bottom-8 left-1/2 z-40 flex items-center gap-2 cursor-pointer
                             bg-card/50 backdrop-blur-md border border-border/50 shadow-lg
                             rounded-xl px-6 h-12
                             animate-slide-up-fade hover:text-foreground text-muted-foreground"
                >
                  <span className="text-sm font-medium">← Back to Scanner</span>
                </AnimatedButton>
              </div>
            ) : (
              <ScannerPanel onScanComplete={handleScanComplete} />
            )}
          </TabsContent>

          <TabsContent value="analytics" className="mt-0">
            <AnalyticsPanel refreshKey={refreshKey} />
          </TabsContent>
        </Tabs>
      </main>

    </div>
  );
}
