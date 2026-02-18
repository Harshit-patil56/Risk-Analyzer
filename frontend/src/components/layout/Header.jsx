"use client";

import { ShieldCheck, List } from "@phosphor-icons/react";
import { Button } from "@/components/ui/button";
import ThemeToggle from "./ThemeToggle";

export default function Header({ onMenuClick, sidebarOpen }) {
    return (
        <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-30">
            <div className="max-w-5xl mx-auto px-4 h-14 flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <Button
                        variant="ghost"
                        size="icon"
                        onClick={onMenuClick}
                        aria-label="Open scan history"
                        className={`cursor-pointer h-9 w-9 transition-all duration-200 ${sidebarOpen
                                ? "opacity-0 scale-75 pointer-events-none"
                                : "opacity-100 scale-100"
                            }`}
                    >
                        <List size={20} weight="regular" className="text-muted-foreground" />
                    </Button>
                    <ShieldCheck size={24} weight="bold" className="text-muted-foreground" />
                    <h1 className="text-lg font-semibold tracking-tight">Risk Analyzer</h1>
                </div>
                <ThemeToggle />
            </div>
        </header>
    );
}
