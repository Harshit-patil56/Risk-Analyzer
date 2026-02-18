"use client";

import { useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
    ChartBar,
    Target,
    TrendUp,
    Scan,
    ToggleLeft,
    ToggleRight,
} from "@phosphor-icons/react";
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from "recharts";
import { scanStore } from "@/lib/sessionStore";

const STATUS_COLORS = {
    safe: "var(--status-safe)",
    suspicious: "var(--status-suspicious)",
    dangerous: "var(--status-dangerous)",
};

function EmptyAnalytics() {
    return (
        <Card className="p-8 border border-border bg-card">
            <div className="flex flex-col items-center gap-4 text-center">
                <div className="w-16 h-16 rounded-full border-2 border-muted flex items-center justify-center">
                    <ChartBar size={28} weight="regular" className="text-muted-foreground" />
                </div>
                <div>
                    <h3 className="font-medium mb-1">No Scan Data Yet</h3>
                    <p className="text-sm text-muted-foreground">
                        Run your first scan to see analytics here.
                    </p>
                </div>
            </div>
        </Card>
    );
}

export default function AnalyticsPanel({ refreshKey }) {
    const [stats, setStats] = useState(null);
    const [compareByType, setCompareByType] = useState(false);

    useEffect(() => {
        setStats(scanStore.getStats());
    }, [refreshKey]);

    if (!stats || stats.totalScans === 0) {
        return <EmptyAnalytics />;
    }

    const distributionData = [
        { name: "Safe", value: stats.distribution.safe, fill: STATUS_COLORS.safe },
        { name: "Suspicious", value: stats.distribution.suspicious, fill: STATUS_COLORS.suspicious },
        { name: "Dangerous", value: stats.distribution.dangerous, fill: STATUS_COLORS.dangerous },
    ].filter((d) => d.value > 0);

    const indicatorData = Object.entries(stats.indicatorFrequency)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6)
        .map(([name, count]) => ({ name: name.length > 20 ? name.slice(0, 18) + "..." : name, count, fullName: name }));

    return (
        <div className="space-y-4">
            {/* KPI Cards */}
            <div className="grid grid-cols-2 gap-3">
                <Card className="p-4 border border-border bg-card">
                    <div className="flex items-center gap-2 mb-2">
                        <Scan size={18} weight="regular" className="text-muted-foreground" />
                        <span className="text-xs text-muted-foreground font-medium">Total Scans</span>
                    </div>
                    <p className="text-2xl font-bold">{stats.totalScans}</p>
                </Card>

                <Card className="p-4 border border-border bg-card">
                    <div className="flex items-center gap-2 mb-2">
                        <TrendUp size={18} weight="regular" className="text-muted-foreground" />
                        <span className="text-xs text-muted-foreground font-medium">Avg Risk Score</span>
                    </div>
                    <p className="text-2xl font-bold">{stats.averageScore}
                        <span className="text-sm text-muted-foreground font-normal">/ 100</span>
                    </p>
                </Card>
            </div>

            {/* Distribution Chart */}
            <Card className="p-4 border border-border bg-card">
                <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                        <Target size={18} weight="regular" className="text-muted-foreground" />
                        <h3 className="text-sm font-medium">Risk Distribution</h3>
                    </div>
                    <button
                        onClick={() => setCompareByType(!compareByType)}
                        className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
                    >
                        {compareByType ? (
                            <ToggleRight size={18} weight="fill" className="text-muted-foreground" />
                        ) : (
                            <ToggleLeft size={18} weight="regular" className="text-muted-foreground" />
                        )}
                        By Type
                    </button>
                </div>

                {!compareByType ? (
                    <div className="flex items-center gap-6">
                        <div className="w-28 h-28">
                            <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                    <Pie
                                        data={distributionData}
                                        cx="50%"
                                        cy="50%"
                                        innerRadius={30}
                                        outerRadius={50}
                                        paddingAngle={3}
                                        dataKey="value"
                                        stroke="none"
                                    >
                                        {distributionData.map((entry, index) => (
                                            <Cell key={index} fill={entry.fill} />
                                        ))}
                                    </Pie>
                                </PieChart>
                            </ResponsiveContainer>
                        </div>
                        <div className="flex flex-col gap-2">
                            {distributionData.map((d) => (
                                <div key={d.name} className="flex items-center gap-2 text-sm">
                                    <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: d.fill }} />
                                    <span className="text-muted-foreground">{d.name}</span>
                                    <span className="font-medium">{d.value}</span>
                                </div>
                            ))}
                        </div>
                    </div>
                ) : (
                    <div className="flex items-center gap-6">
                        <div className="flex flex-col gap-2 w-full">
                            <div className="flex items-center justify-between text-sm">
                                <span className="text-muted-foreground">URL Scans</span>
                                <span className="font-medium">{stats.byType.url}</span>
                            </div>
                            <div className="h-2 bg-muted rounded-full overflow-hidden">
                                <div
                                    className="h-full rounded-full bg-[var(--chart-4)] transition-all duration-500"
                                    style={{ width: `${stats.totalScans > 0 ? (stats.byType.url / stats.totalScans) * 100 : 0}%` }}
                                />
                            </div>
                            <div className="flex items-center justify-between text-sm mt-1">
                                <span className="text-muted-foreground">Email Scans</span>
                                <span className="font-medium">{stats.byType.email}</span>
                            </div>
                            <div className="h-2 bg-muted rounded-full overflow-hidden">
                                <div
                                    className="h-full rounded-full bg-[var(--chart-5)] transition-all duration-500"
                                    style={{ width: `${stats.totalScans > 0 ? (stats.byType.email / stats.totalScans) * 100 : 0}%` }}
                                />
                            </div>
                        </div>
                    </div>
                )}
            </Card>

            {/* Common Indicators */}
            {indicatorData.length > 0 && (
                <Card className="p-4 border border-border bg-card">
                    <div className="flex items-center gap-2 mb-3">
                        <ChartBar size={18} weight="regular" className="text-muted-foreground" />
                        <h3 className="text-sm font-medium">Most Common Indicators</h3>
                    </div>
                    <div className="h-48">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={indicatorData} layout="vertical" margin={{ left: 0, right: 20 }}>
                                <XAxis type="number" tick={{ fontSize: 11 }} stroke="var(--muted-foreground)" />
                                <YAxis
                                    type="category"
                                    dataKey="name"
                                    width={110}
                                    tick={{ fontSize: 11 }}
                                    stroke="var(--muted-foreground)"
                                />
                                <Tooltip
                                    formatter={(value, name, props) => [value, props.payload.fullName]}
                                    contentStyle={{
                                        backgroundColor: "var(--card)",
                                        border: "1px solid var(--border)",
                                        borderRadius: "8px",
                                        fontSize: "12px",
                                    }}
                                />
                                <Bar dataKey="count" fill="var(--chart-4)" radius={[0, 4, 4, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </Card>
            )}
        </div>
    );
}
