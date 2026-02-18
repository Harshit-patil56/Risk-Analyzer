"use client";

import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
    ShieldCheck,
    ShieldWarning,
    Warning,
    CaretDown,
    CaretUp,
    CloudCheck,
    CloudSlash,
    Brain,
} from "@phosphor-icons/react";

const STATUS_CONFIG = {
    safe: {
        color: "var(--status-safe)",
        bg: "var(--status-safe-bg)",
        icon: ShieldCheck,
        label: "Safe",
    },
    suspicious: {
        color: "var(--status-suspicious)",
        bg: "var(--status-suspicious-bg)",
        icon: ShieldWarning,
        label: "Suspicious",
    },
    dangerous: {
        color: "var(--status-dangerous)",
        bg: "var(--status-dangerous-bg)",
        icon: Warning,
        label: "Dangerous",
    },
};

function RiskGauge({ score, label }) {
    const config = STATUS_CONFIG[label] || STATUS_CONFIG.safe;
    const circumference = 2 * Math.PI * 45;
    const offset = circumference - (score / 100) * circumference;

    return (
        <div className="flex flex-col items-center gap-2">
            <div className="relative w-32 h-32">
                <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                    <circle
                        cx="50" cy="50" r="45"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="8"
                        className="text-muted/50"
                    />
                    <circle
                        cx="50" cy="50" r="45"
                        fill="none"
                        stroke={config.color}
                        strokeWidth="8"
                        strokeLinecap="round"
                        strokeDasharray={circumference}
                        strokeDashoffset={offset}
                        className="gauge-animate"
                    />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-3xl font-bold" style={{ color: config.color }}>
                        {score}
                    </span>
                    <span className="text-xs text-muted-foreground">/ 100</span>
                </div>
            </div>
            <Badge
                className="text-sm font-medium px-3 py-1"
                style={{ backgroundColor: config.bg, color: config.color, border: `1px solid ${config.color}30` }}
            >
                {config.label}
            </Badge>
        </div>
    );
}

function SubScoreBar({ name, score, maxScore = 100 }) {
    const percentage = (score / maxScore) * 100;
    let barColor = "var(--status-safe)";
    if (score > 60) barColor = "var(--status-dangerous)";
    else if (score > 30) barColor = "var(--status-suspicious)";

    return (
        <div className="space-y-1">
            <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">{name}</span>
                <span className="font-medium">{score}</span>
            </div>
            <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                    className="h-full rounded-full transition-all duration-700 ease-out"
                    style={{ width: `${percentage}%`, backgroundColor: barColor }}
                />
            </div>
        </div>
    );
}

function ThreatIndicators({ indicators }) {
    if (!indicators || indicators.length === 0) return null;

    const severityConfig = {
        high: { color: "var(--status-dangerous)", bg: "var(--status-dangerous-bg)" },
        medium: { color: "var(--status-suspicious)", bg: "var(--status-suspicious-bg)" },
        low: { color: "var(--status-safe)", bg: "var(--status-safe-bg)" },
    };

    return (
        <div className="space-y-2">
            <h3 className="text-sm font-medium text-muted-foreground">Detected Indicators</h3>
            <div className="space-y-2">
                {indicators.map((ind, i) => {
                    const config = severityConfig[ind.severity] || severityConfig.low;
                    return (
                        <div
                            key={i}
                            className="p-3 rounded-lg border border-border bg-card/50"
                        >
                            <div className="flex items-center gap-2 mb-1">
                                <Badge
                                    className="text-xs"
                                    style={{ backgroundColor: config.bg, color: config.color, border: `1px solid ${config.color}30` }}
                                >
                                    {ind.severity}
                                </Badge>
                                <span className="text-sm font-medium">{ind.name}</span>
                            </div>
                            <p className="text-xs text-muted-foreground leading-relaxed">{ind.explanation}</p>
                        </div>
                    );
                })}
            </div>
        </div>
    );
}

export default function RiskScorecard({ result }) {
    const [expanded, setExpanded] = useState(false);

    if (!result) return null;

    const { overall_score, label, sub_scores, indicators, api_status, ml_status } = result;

    return (
        <Card className="p-6 border border-border bg-card">
            {/* Main score */}
            <div className="flex flex-col items-center mb-6">
                <RiskGauge score={overall_score} label={label} />
            </div>

            {/* Scanned input */}
            <div className="mb-4 px-3 py-2 rounded-md bg-muted/50 border border-border">
                <p className="text-xs text-muted-foreground mb-0.5">Scanned Input</p>
                <p className="text-sm font-mono break-all">{result.scanned_input}</p>
            </div>

            {/* Sub-scores expandable */}
            <button
                onClick={() => setExpanded(!expanded)}
                className="w-full flex items-center justify-between text-sm font-medium text-muted-foreground hover:text-foreground transition-colors mb-3 cursor-pointer"
            >
                <span>Score Breakdown</span>
                {expanded ? <CaretUp size={16} weight="bold" /> : <CaretDown size={16} weight="bold" />}
            </button>

            {expanded && (
                <div className="space-y-3 mb-4 pb-4 border-b border-border">
                    <SubScoreBar name="Domain Risk" score={sub_scores.domain} />
                    <SubScoreBar name="Structural Risk" score={sub_scores.structural} />
                    <SubScoreBar name="Language Risk" score={sub_scores.language} />
                    <SubScoreBar name="API Reputation" score={sub_scores.api_reputation} />

                    {/* Status indicators */}
                    <div className="flex flex-wrap gap-2 mt-3">
                        <div className="flex items-center gap-1 text-xs text-muted-foreground">
                            <Brain size={14} weight="regular" className="text-muted-foreground" />
                            ML: {ml_status === "available" ? "Active" : "Offline"}
                        </div>
                        {api_status && Object.entries(api_status).map(([api, status]) => (
                            <div key={api} className="flex items-center gap-1 text-xs text-muted-foreground">
                                {status === "available" ? (
                                    <CloudCheck size={14} weight="regular" className="text-muted-foreground" />
                                ) : (
                                    <CloudSlash size={14} weight="regular" className="text-muted-foreground" />
                                )}
                                {api.replace("_", " ")}
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Threat indicators */}
            <ThreatIndicators indicators={indicators} />
        </Card>
    );
}
