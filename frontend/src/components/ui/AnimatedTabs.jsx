"use client";

import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

export function AnimatedTabs({
    options,
    value,
    onChange,
    className,
    layoutId = "activeTab"
}) {
    return (
        <div className={cn("flex p-1 bg-muted/50 rounded-xl relative", className)}>
            {options.map((option) => {
                const isActive = value === option.value;
                return (
                    <button
                        key={option.value}
                        onClick={() => onChange(option.value)}
                        className={cn(
                            "relative flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm font-medium transition-all outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 rounded-lg z-10 cursor-pointer",
                            isActive
                                ? "text-foreground"
                                : "text-muted-foreground hover:text-foreground"
                        )}
                        style={{
                            WebkitTapHighlightColor: "transparent",
                        }}
                    >
                        {isActive && (
                            <motion.div
                                layoutId={layoutId}
                                className="absolute inset-0 bg-card dark:bg-neutral-900 rounded-lg shadow-md border border-border/50"
                                initial={false}
                                transition={{
                                    type: "spring",
                                    stiffness: 400,
                                    damping: 30,
                                }}
                                style={{ zIndex: -1 }}
                            />
                        )}
                        {option.icon && (
                            <option.icon
                                size={16}
                                weight={isActive ? "fill" : "regular"}
                                className="relative z-10"
                            />
                        )}
                        <span className="relative z-10">{option.label}</span>
                    </button>
                );
            })}
        </div>
    );
}

export function AnimatedButton({ children, onClick, className, ...props }) {
    return (
        <motion.button
            onClick={onClick}
            className={className}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.96 }}
            transition={{
                type: "spring",
                stiffness: 400,
                damping: 17
            }}
            {...props}
        >
            {children}
        </motion.button>
    );
}
