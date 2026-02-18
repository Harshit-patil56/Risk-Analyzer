"use client";

import { Card } from "@/components/ui/card";
import { Lightbulb, BookOpen } from "@phosphor-icons/react";

export default function EducationalModule({ education, label }) {
    if (!education || education.length === 0) return null;

    return (
        <Card className="p-6 border border-border bg-card">
            <div className="flex items-center gap-2 mb-4">
                <BookOpen size={20} weight="regular" className="text-muted-foreground" />
                <h2 className="text-base font-semibold">Learn & Protect</h2>
            </div>

            <div className="space-y-3">
                {education.map((item, i) => (
                    <div
                        key={i}
                        className="p-3 rounded-lg border border-border bg-card/50"
                    >
                        <div className="flex items-start gap-2.5">
                            <Lightbulb size={18} weight="regular" className="text-muted-foreground mt-0.5 shrink-0" />
                            <div>
                                <h3 className="text-sm font-medium mb-1">{item.title}</h3>
                                <p className="text-xs text-muted-foreground leading-relaxed">{item.content}</p>
                            </div>
                        </div>
                    </div>
                ))}
            </div>
        </Card>
    );
}
