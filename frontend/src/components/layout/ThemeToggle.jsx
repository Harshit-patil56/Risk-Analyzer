"use client";

import { useEffect, useState } from "react";
import { Moon, Sun } from "@phosphor-icons/react";
import { Button } from "@/components/ui/button";

export default function ThemeToggle() {
    const [dark, setDark] = useState(false);

    useEffect(() => {
        const stored = localStorage.getItem("theme");
        const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
        const isDark = stored === "dark" || (!stored && prefersDark);
        setDark(isDark);
        document.documentElement.classList.toggle("dark", isDark);
    }, []);

    function toggle() {
        const next = !dark;
        setDark(next);
        document.documentElement.classList.toggle("dark", next);
        localStorage.setItem("theme", next ? "dark" : "light");
    }

    return (
        <Button
            variant="ghost"
            size="icon"
            onClick={toggle}
            aria-label="Toggle dark mode"
            className="cursor-pointer"
        >
            {dark ? (
                <Sun size={20} weight="regular" className="text-muted-foreground" />
            ) : (
                <Moon size={20} weight="regular" className="text-muted-foreground" />
            )}
        </Button>
    );
}
