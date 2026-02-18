"use client";

import { useEffect, useState } from "react";
import {
    X,
    Globe,
    EnvelopeSimple,
    Trash,
    ClockCounterClockwise,
    TrashSimple,
} from "@phosphor-icons/react";
import { Button } from "@/components/ui/button";
import { scanStore } from "@/lib/sessionStore";

const STATUS_COLORS = {
    safe: "var(--status-safe)",
    suspicious: "var(--status-suspicious)",
    dangerous: "var(--status-dangerous)",
};

function formatTime(isoString) {
    const date = new Date(isoString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHrs = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 1) return "Just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHrs < 24) return `${diffHrs}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
}

function truncateInput(input, max = 36) {
    if (!input) return "Unknown";
    return input.length > max ? input.slice(0, max - 3) + "..." : input;
}

export default function HistorySidebar({ open, onClose, onSelectScan, refreshKey }) {
    const [scans, setScans] = useState([]);

    useEffect(() => {
        if (open) {
            setScans(scanStore.getAll().reverse());
        }
    }, [open, refreshKey]);

    function handleDelete(e, id) {
        e.stopPropagation();
        scanStore.deleteById(id);
        setScans(scanStore.getAll().reverse());
    }

    function handleClearAll() {
        scanStore.clear();
        setScans([]);
    }

    return (
        <>
            {/* Backdrop overlay */}
            {open && (
                <div
                    className="fixed inset-0 bg-black/30 z-40 transition-opacity"
                    onClick={onClose}
                />
            )}

            {/* Sidebar panel */}
            <aside
                className={`fixed top-0 left-0 h-full w-72 bg-card border-r border-border z-50 flex flex-col transition-transform duration-200 ease-out ${open ? "translate-x-0" : "-translate-x-full"
                    }`}
            >
                {/* Header */}
                <div className="h-14 px-4 flex items-center justify-between border-b border-border shrink-0">
                    <div className="flex items-center gap-2">
                        <ClockCounterClockwise size={18} weight="regular" className="text-muted-foreground" />
                        <span className="text-sm font-semibold">Scan History</span>
                    </div>
                    <Button
                        variant="ghost"
                        size="icon"
                        onClick={onClose}
                        aria-label="Close sidebar"
                        className="cursor-pointer h-8 w-8"
                    >
                        <X size={18} weight="regular" className="text-muted-foreground" />
                    </Button>
                </div>

                {/* Scan list */}
                <div className="flex-1 overflow-y-auto">
                    {scans.length === 0 ? (
                        <div className="flex flex-col items-center justify-center h-full text-center px-6">
                            <ClockCounterClockwise size={32} weight="regular" className="text-muted-foreground/40 mb-3" />
                            <p className="text-sm text-muted-foreground">No scans yet</p>
                            <p className="text-xs text-muted-foreground/60 mt-1">
                                Your scan history will appear here
                            </p>
                        </div>
                    ) : (
                        <div className="py-2">
                            {scans.map((scan) => (
                                <div
                                    key={scan.id}
                                    role="button"
                                    tabIndex={0}
                                    onClick={() => {
                                        onSelectScan(scan);
                                        onClose();
                                    }}
                                    onKeyDown={(e) => {
                                        if (e.key === "Enter") {
                                            onSelectScan(scan);
                                            onClose();
                                        }
                                    }}
                                    className="w-full text-left px-4 py-3 hover:bg-accent/50 transition-colors group cursor-pointer border-b border-border/50 last:border-b-0"
                                >
                                    <div className="flex items-start justify-between gap-2">
                                        <div className="flex items-center gap-2 min-w-0">
                                            {scan.scan_type === "url" ? (
                                                <Globe size={14} weight="regular" className="text-muted-foreground shrink-0 mt-0.5" />
                                            ) : (
                                                <EnvelopeSimple size={14} weight="regular" className="text-muted-foreground shrink-0 mt-0.5" />
                                            )}
                                            <span className="text-sm truncate">
                                                {truncateInput(scan.scanned_input)}
                                            </span>
                                        </div>

                                        {/* Delete button — visible on hover */}
                                        <button
                                            onClick={(e) => handleDelete(e, scan.id)}
                                            className="opacity-0 group-hover:opacity-100 transition-opacity p-1 hover:bg-muted rounded cursor-pointer shrink-0"
                                            aria-label="Delete scan"
                                        >
                                            <Trash size={14} weight="regular" className="text-muted-foreground" />
                                        </button>
                                    </div>

                                    <div className="flex items-center gap-2 mt-1.5 pl-6">
                                        <span
                                            className="w-2 h-2 rounded-full shrink-0"
                                            style={{ backgroundColor: STATUS_COLORS[scan.label] || STATUS_COLORS.safe }}
                                        />
                                        <span className="text-xs text-muted-foreground">
                                            {scan.overall_score}/100
                                        </span>
                                        <span className="text-xs text-muted-foreground/50">·</span>
                                        <span className="text-xs text-muted-foreground/60">
                                            {formatTime(scan.timestamp)}
                                        </span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Footer — clear all */}
                {scans.length > 0 && (
                    <div className="px-4 py-3 border-t border-border shrink-0">
                        <button
                            onClick={handleClearAll}
                            className="w-full flex items-center justify-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors cursor-pointer py-1.5"
                        >
                            <TrashSimple size={14} weight="regular" className="text-muted-foreground" />
                            Clear All History
                        </button>
                    </div>
                )}
            </aside>
        </>
    );
}
