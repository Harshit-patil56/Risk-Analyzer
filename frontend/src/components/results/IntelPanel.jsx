"use client";

import { useState } from "react";
import {
    Globe,
    LockSimple,
    LockSimpleOpen,
    MapPin,
    ArrowsClockwise,
    Calendar,
    Buildings,
    CaretDown,
    CaretUp,
    LinkSimple,
    ShieldWarning,
    Eye,
} from "@phosphor-icons/react";

function InfoItem({ icon: Icon, label, value, color }) {
    if (!value && value !== 0) return null;
    return (
        <div className="flex items-start gap-2 py-1.5">
            <Icon size={14} weight="regular" className="text-muted-foreground shrink-0 mt-0.5" />
            <span className="text-xs text-muted-foreground">{label}:</span>
            <span className={`text-xs font-medium ${color || ""}`}>{value}</span>
        </div>
    );
}

function IntelSection({ title, icon: Icon, children, defaultOpen = false }) {
    const [open, setOpen] = useState(defaultOpen);
    return (
        <div className="border border-border rounded-lg overflow-hidden">
            <button
                onClick={() => setOpen(!open)}
                className="w-full flex items-center justify-between px-4 py-3 hover:bg-accent/30 transition-colors cursor-pointer"
            >
                <div className="flex items-center gap-2">
                    <Icon size={16} weight="regular" className="text-muted-foreground" />
                    <span className="text-sm font-medium">{title}</span>
                </div>
                {open ? (
                    <CaretUp size={14} weight="regular" className="text-muted-foreground" />
                ) : (
                    <CaretDown size={14} weight="regular" className="text-muted-foreground" />
                )}
            </button>
            {open && <div className="px-4 pb-3 border-t border-border/50">{children}</div>}
        </div>
    );
}

function formatDomainAge(days) {
    if (days === null || days === undefined) return null;
    if (days < 30) return `${days} days (⚠ Very new)`;
    if (days < 365) return `${Math.floor(days / 30)} months`;
    return `${Math.floor(days / 365)} years, ${Math.floor((days % 365) / 30)} months`;
}

function formatDate(iso) {
    if (!iso) return null;
    return new Date(iso).toLocaleDateString("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric",
    });
}

export default function IntelPanel({ intel }) {
    if (!intel) return null;

    const { whois, ssl, dns_geo, unshorten, screenshot } = intel;

    return (
        <div className="space-y-3 mt-4">
            <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
                URL Intelligence
            </h3>

            {/* Unshortened URL alert */}
            {unshorten?.is_shortened && (
                <div className="flex items-start gap-2 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
                    <ShieldWarning size={16} weight="regular" className="text-muted-foreground shrink-0 mt-0.5" />
                    <div>
                        <p className="text-xs font-medium">Shortened URL Expanded</p>
                        <p className="text-xs text-muted-foreground mt-0.5 break-all">
                            → {unshorten.final_url}
                        </p>
                        {unshorten.redirect_chain_length > 1 && (
                            <p className="text-xs text-muted-foreground/60 mt-0.5">
                                {unshorten.redirect_chain_length} redirects
                            </p>
                        )}
                    </div>
                </div>
            )}

            {/* WHOIS */}
            {whois?.available && (
                <IntelSection title="WHOIS Registration" icon={Globe} defaultOpen={true}>
                    <div className="divide-y divide-border/30">
                        <InfoItem icon={Buildings} label="Registrar" value={whois.registrar} />
                        <InfoItem icon={Calendar} label="Created" value={formatDate(whois.creation_date)} />
                        <InfoItem icon={Calendar} label="Expires" value={formatDate(whois.expiration_date)} />
                        <InfoItem
                            icon={ArrowsClockwise}
                            label="Domain Age"
                            value={formatDomainAge(whois.domain_age_days)}
                            color={whois.domain_age_days !== null && whois.domain_age_days < 30 ? "text-amber-400" : ""}
                        />
                        {whois.org && <InfoItem icon={Buildings} label="Organization" value={whois.org} />}
                        {whois.country && <InfoItem icon={MapPin} label="Country" value={whois.country} />}
                    </div>
                </IntelSection>
            )}

            {/* SSL Certificate */}
            {ssl?.available && (
                <IntelSection title="SSL Certificate" icon={ssl.is_expired ? LockSimpleOpen : LockSimple}>
                    <div className="divide-y divide-border/30">
                        <InfoItem icon={LockSimple} label="Subject" value={ssl.subject} />
                        <InfoItem icon={Buildings} label="Issuer" value={ssl.issuer} />
                        <InfoItem icon={Calendar} label="Issued" value={formatDate(ssl.issued_date)} />
                        <InfoItem
                            icon={Calendar}
                            label="Expires"
                            value={formatDate(ssl.expiry_date)}
                            color={ssl.is_expired ? "text-red-400" : ""}
                        />
                        {ssl.is_expired && (
                            <div className="py-1.5">
                                <span className="text-xs text-red-400 font-medium">⚠ Certificate is expired</span>
                            </div>
                        )}
                        {ssl.error && (
                            <div className="py-1.5">
                                <span className="text-xs text-amber-400 font-medium">⚠ {ssl.error}</span>
                            </div>
                        )}
                    </div>
                </IntelSection>
            )}

            {/* DNS / IP Geolocation */}
            {dns_geo?.available && (
                <IntelSection title="DNS / IP Location" icon={MapPin}>
                    <div className="divide-y divide-border/30">
                        <InfoItem icon={Globe} label="IP Address" value={dns_geo.ip_address} />
                        {dns_geo.country && (
                            <InfoItem icon={MapPin} label="Location" value={[dns_geo.city, dns_geo.region, dns_geo.country].filter(Boolean).join(", ")} />
                        )}
                        {dns_geo.isp && <InfoItem icon={Buildings} label="ISP" value={dns_geo.isp} />}
                        {dns_geo.org && <InfoItem icon={Buildings} label="Organization" value={dns_geo.org} />}
                        {dns_geo.asn && <InfoItem icon={Globe} label="ASN" value={dns_geo.asn} />}
                    </div>
                </IntelSection>
            )}

            {/* Screenshot */}
            {screenshot?.available && screenshot?.url && (
                <IntelSection title="Page Preview" icon={Eye}>
                    <div className="mt-2 rounded-lg overflow-hidden border border-border/50">
                        {/* eslint-disable-next-line @next/next/no-img-element */}
                        <img
                            src={screenshot.url}
                            alt="Website preview"
                            className="w-full h-auto"
                            loading="lazy"
                        />
                    </div>
                    <p className="text-xs text-muted-foreground/50 mt-2 text-center">
                        Preview via thum.io — page is not loaded in your browser
                    </p>
                </IntelSection>
            )}
        </div>
    );
}
