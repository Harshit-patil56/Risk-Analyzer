"use client";

import { useState, useCallback, useRef } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
    Globe,
    EnvelopeSimple,
    MagnifyingGlass,
    CircleNotch,
    QrCode,
    ListBullets,
    UploadSimple,
    X,
} from "@phosphor-icons/react";
import RiskScorecard from "@/components/results/RiskScorecard";
import EducationalModule from "@/components/results/EducationalModule";
import IntelPanel from "@/components/results/IntelPanel";
import { scanUrl, scanEmail, scanQr, scanBulk } from "@/lib/api";
import { scanStore } from "@/lib/sessionStore";
import { AnimatedTabs, AnimatedButton } from "@/components/ui/AnimatedTabs";

export default function ScannerPanel({ onScanComplete }) {
    const [inputType, setInputType] = useState("url");
    const [urlValue, setUrlValue] = useState("");
    const [emailValue, setEmailValue] = useState("");
    const [bulkValue, setBulkValue] = useState("");
    const [qrFile, setQrFile] = useState(null);
    const [qrPreview, setQrPreview] = useState(null);
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [bulkResult, setBulkResult] = useState(null);
    const [error, setError] = useState(null);
    const fileInputRef = useRef(null);

    const handleScan = useCallback(async () => {
        setError(null);
        setResult(null);
        setBulkResult(null);
        setLoading(true);

        try {
            let data;
            if (inputType === "url") {
                if (!urlValue.trim()) { setError("Please enter a URL to scan."); setLoading(false); return; }
                data = await scanUrl(urlValue.trim());
                setResult(data);
                scanStore.save(data);
            } else if (inputType === "email") {
                if (!emailValue.trim()) { setError("Please paste email content to scan."); setLoading(false); return; }
                data = await scanEmail(emailValue.trim());
                setResult(data);
                scanStore.save(data);
            } else if (inputType === "qr") {
                if (!qrFile) { setError("Please upload a QR code image."); setLoading(false); return; }
                data = await scanQr(qrFile);
                setResult(data);
                scanStore.save(data);
            } else if (inputType === "bulk") {
                const urls = bulkValue.split("\n").map(u => u.trim()).filter(Boolean);
                if (urls.length === 0) { setError("Please enter at least one URL."); setLoading(false); return; }
                if (urls.length > 10) { setError("Maximum 10 URLs per bulk scan."); setLoading(false); return; }
                data = await scanBulk(urls);
                setBulkResult(data);
                // Save each result individually
                (data.results || []).forEach(r => { if (r.overall_score !== null) scanStore.save(r); });
            }
            if (onScanComplete) onScanComplete();
        } catch (err) {
            setError(err.message || "Failed to connect to the analysis server. Is the backend running?");
        } finally {
            setLoading(false);
        }
    }, [inputType, urlValue, emailValue, qrFile, bulkValue, onScanComplete]);

    const handleReset = () => {
        setResult(null);
        setBulkResult(null);
        setError(null);
        setUrlValue("");
        setEmailValue("");
        setBulkValue("");
        setQrFile(null);
        setQrPreview(null);
    };

    const handleQrFileChange = (e) => {
        const file = e.target.files?.[0];
        if (!file) return;
        setQrFile(file);
        // Generate preview
        const reader = new FileReader();
        reader.onloadend = () => setQrPreview(reader.result);
        reader.readAsDataURL(file);
    };

    const removeQrFile = () => {
        setQrFile(null);
        setQrPreview(null);
        if (fileInputRef.current) fileInputRef.current.value = "";
    };

    const inputReady =
        inputType === "url" ? urlValue.trim().length > 0 :
            inputType === "email" ? emailValue.trim().length >= 10 :
                inputType === "qr" ? qrFile !== null :
                    inputType === "bulk" ? bulkValue.trim().length > 0 :
                        false;

    const scanLabel =
        inputType === "url" ? "URL" :
            inputType === "email" ? "Email" :
                inputType === "qr" ? "QR Code" :
                    "Bulk URLs";

    return (
        <div className="space-y-6">
            {/* Input Section */}
            {!result && !bulkResult && (
                <Card className="p-6 border border-border bg-card">
                    <Tabs value={inputType} onValueChange={setInputType}>
                        <div className="mb-6">
                            <AnimatedTabs
                                value={inputType}
                                onChange={setInputType}
                                options={[
                                    { value: "url", label: "URL", icon: Globe },
                                    { value: "email", label: "Email", icon: EnvelopeSimple },
                                    { value: "qr", label: "QR Code", icon: QrCode },
                                    { value: "bulk", label: "Bulk", icon: ListBullets },
                                ]}
                                layoutId="scanner-tabs"
                            />
                        </div>

                        <TabsContent value="url" className="space-y-4">
                            <div>
                                <label htmlFor="url-input" className="text-sm font-medium text-muted-foreground mb-1.5 block">
                                    Paste a URL to analyze
                                </label>
                                <Input
                                    id="url-input"
                                    placeholder="https://example.com/suspicious-link"
                                    value={urlValue}
                                    onChange={(e) => setUrlValue(e.target.value)}
                                    onKeyDown={(e) => e.key === "Enter" && inputReady && !loading && handleScan()}
                                    disabled={loading}
                                    className="font-mono text-sm"
                                />
                            </div>
                        </TabsContent>

                        <TabsContent value="email" className="space-y-4">
                            <div>
                                <label htmlFor="email-input" className="text-sm font-medium text-muted-foreground mb-1.5 block">
                                    Paste email content to analyze
                                </label>
                                <Textarea
                                    id="email-input"
                                    placeholder="Dear Customer, Your account has been suspended. Click here to verify..."
                                    value={emailValue}
                                    onChange={(e) => setEmailValue(e.target.value)}
                                    disabled={loading}
                                    rows={6}
                                    className="text-sm resize-none"
                                />
                            </div>
                        </TabsContent>

                        <TabsContent value="qr" className="space-y-4">
                            <div>
                                <label className="text-sm font-medium text-muted-foreground mb-1.5 block">
                                    Upload a QR code image
                                </label>
                                {!qrFile ? (
                                    <div
                                        onClick={() => fileInputRef.current?.click()}
                                        className="border-2 border-dashed border-border rounded-lg p-8 flex flex-col items-center gap-3 hover:border-muted-foreground/50 transition-colors cursor-pointer"
                                    >
                                        <UploadSimple size={32} weight="regular" className="text-muted-foreground/40" />
                                        <p className="text-sm text-muted-foreground">Click to upload QR code image</p>
                                        <p className="text-xs text-muted-foreground/50">PNG, JPG, or WebP</p>
                                    </div>
                                ) : (
                                    <div className="border border-border rounded-lg p-4 flex items-center gap-4">
                                        {qrPreview && (
                                            // eslint-disable-next-line @next/next/no-img-element
                                            <img src={qrPreview} alt="QR preview" className="w-20 h-20 object-contain rounded" />
                                        )}
                                        <div className="flex-1 min-w-0">
                                            <p className="text-sm font-medium truncate">{qrFile.name}</p>
                                            <p className="text-xs text-muted-foreground">{(qrFile.size / 1024).toFixed(1)} KB</p>
                                        </div>
                                        <button onClick={removeQrFile} className="p-1 hover:bg-muted rounded cursor-pointer">
                                            <X size={16} weight="regular" className="text-muted-foreground" />
                                        </button>
                                    </div>
                                )}
                                <input
                                    ref={fileInputRef}
                                    type="file"
                                    accept="image/*"
                                    onChange={handleQrFileChange}
                                    className="hidden"
                                />
                            </div>
                        </TabsContent>

                        <TabsContent value="bulk" className="space-y-4">
                            <div>
                                <label htmlFor="bulk-input" className="text-sm font-medium text-muted-foreground mb-1.5 block">
                                    Paste URLs (one per line, max 10)
                                </label>
                                <Textarea
                                    id="bulk-input"
                                    placeholder={"https://google.com\nhttps://suspicious-site.xyz\nhttps://github.com"}
                                    value={bulkValue}
                                    onChange={(e) => setBulkValue(e.target.value)}
                                    disabled={loading}
                                    rows={6}
                                    className="font-mono text-sm resize-none"
                                />
                                <p className="text-xs text-muted-foreground/60 mt-1">
                                    {bulkValue.split("\n").filter(u => u.trim()).length}/10 URLs
                                </p>
                            </div>
                        </TabsContent>
                    </Tabs>

                    {error && (
                        <div className="mt-3 px-3 py-2 rounded-md bg-[var(--status-dangerous-bg)] border border-[var(--status-dangerous)]/20">
                            <p className="text-sm" style={{ color: "var(--status-dangerous)" }}>{error}</p>
                        </div>
                    )}

                    <div className="mt-4">
                        <Button
                            onClick={handleScan}
                            disabled={!inputReady || loading}
                            className="w-full gap-2 cursor-pointer"
                            size="lg"
                        >
                            {loading ? (
                                <>
                                    <CircleNotch size={18} weight="bold" className="animate-spin" />
                                    Analyzing...
                                </>
                            ) : (
                                <>
                                    <MagnifyingGlass size={18} weight="bold" />
                                    Scan {scanLabel}
                                </>
                            )}
                        </Button>
                    </div>
                </Card>
            )}

            {/* Loading State */}
            {loading && (
                <Card className="p-8 border border-border bg-card">
                    <div className="flex flex-col items-center gap-4 scan-pulse">
                        <div className="w-16 h-16 rounded-full border-2 border-muted flex items-center justify-center">
                            <MagnifyingGlass size={28} weight="bold" className="text-muted-foreground" />
                        </div>
                        <div className="text-center">
                            <p className="font-medium">Scanning for threats...</p>
                            <p className="text-sm text-muted-foreground mt-1">
                                Running heuristic analysis, API checks, and intelligence gathering
                            </p>
                        </div>
                    </div>
                </Card>
            )}

            {/* Single Scan Results */}
            {result && !loading && (
                <div className="space-y-4">
                    <RiskScorecard result={result} />
                    {result.intel && <IntelPanel intel={result.intel} />}
                    <EducationalModule education={result.education} label={result.label} />
                    <div className="h-20" /> {/* Spacer for floating button */}
                    <div className="h-24" /> {/* Spacer for floating button */}
                    <div className="h-24" /> {/* Spacer for floating button */}
                    <AnimatedButton
                        onClick={handleReset}
                        className="fixed bottom-8 left-1/2 z-40 gap-2 cursor-pointer
                                   bg-card/50 backdrop-blur-md border border-border/50 shadow-lg
                                   rounded-xl px-6 h-12
                                   animate-slide-up-fade hover:text-foreground text-muted-foreground
                                   flex items-center"
                    >
                        <MagnifyingGlass size={18} weight="regular" className="mr-2" />
                        <span className="font-medium">Scan Another</span>
                    </AnimatedButton>
                </div>
            )}

            {/* Bulk Scan Results */}
            {bulkResult && !loading && (
                <div className="space-y-4">
                    {/* Summary card */}
                    <Card className="p-5 border border-border bg-card">
                        <h3 className="text-sm font-semibold mb-3">Bulk Scan Summary</h3>
                        <div className="grid grid-cols-3 gap-4">
                            <div className="text-center">
                                <p className="text-2xl font-bold">{bulkResult.summary.scanned}</p>
                                <p className="text-xs text-muted-foreground">Scanned</p>
                            </div>
                            <div className="text-center">
                                <p className="text-2xl font-bold">{bulkResult.summary.avg_score}</p>
                                <p className="text-xs text-muted-foreground">Avg Score</p>
                            </div>
                            <div className="text-center">
                                <p className="text-2xl font-bold" style={{ color: "var(--status-dangerous)" }}>
                                    {bulkResult.summary.highest_risk}
                                </p>
                                <p className="text-xs text-muted-foreground">Highest Risk</p>
                            </div>
                        </div>
                        <div className="flex items-center justify-center gap-4 mt-4 pt-3 border-t border-border/50">
                            <div className="flex items-center gap-1.5">
                                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: "var(--status-safe)" }} />
                                <span className="text-xs text-muted-foreground">{bulkResult.summary.distribution.safe} Safe</span>
                            </div>
                            <div className="flex items-center gap-1.5">
                                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: "var(--status-suspicious)" }} />
                                <span className="text-xs text-muted-foreground">{bulkResult.summary.distribution.suspicious} Suspicious</span>
                            </div>
                            <div className="flex items-center gap-1.5">
                                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: "var(--status-dangerous)" }} />
                                <span className="text-xs text-muted-foreground">{bulkResult.summary.distribution.dangerous} Dangerous</span>
                            </div>
                        </div>
                    </Card>

                    {/* Individual results */}
                    {bulkResult.results.map((r, i) => (
                        <Card key={i} className="p-4 border border-border bg-card">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2 min-w-0">
                                    <Globe size={14} weight="regular" className="text-muted-foreground shrink-0" />
                                    <span className="text-sm font-mono truncate">{r.scanned_input}</span>
                                </div>
                                {r.overall_score !== null ? (
                                    <div className="flex items-center gap-2 shrink-0">
                                        <span
                                            className="w-2 h-2 rounded-full"
                                            style={{
                                                backgroundColor:
                                                    r.label === "safe" ? "var(--status-safe)" :
                                                        r.label === "suspicious" ? "var(--status-suspicious)" :
                                                            "var(--status-dangerous)"
                                            }}
                                        />
                                        <span className="text-sm font-medium">{r.overall_score}/100</span>
                                        <span className="text-xs text-muted-foreground capitalize">{r.label}</span>
                                    </div>
                                ) : (
                                    <span className="text-xs text-red-400">Error</span>
                                )}
                            </div>
                        </Card>
                    ))}

                    <div className="h-20" /> {/* Spacer for floating button */}
                    <div className="h-24" /> {/* Spacer for floating button */}
                    <AnimatedButton
                        onClick={handleReset}
                        className="fixed bottom-8 left-1/2 z-40 gap-2 cursor-pointer
                                   bg-card/50 backdrop-blur-md border border-border/50 shadow-lg
                                   rounded-xl px-6 h-12
                                   animate-slide-up-fade hover:text-foreground text-muted-foreground
                                   flex items-center"
                    >
                        <MagnifyingGlass size={18} weight="regular" className="mr-2" />
                        <span className="font-medium">Scan Again</span>
                    </AnimatedButton>
                </div>
            )}
        </div>
    );
}
