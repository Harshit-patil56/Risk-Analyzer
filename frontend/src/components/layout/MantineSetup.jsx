"use client";

import { MantineProvider } from "@mantine/core";

export default function MantineSetup({ children }) {
    return (
        <MantineProvider withCSSVariables withNormalizeCSS={false}>
            {children}
        </MantineProvider>
    );
}
