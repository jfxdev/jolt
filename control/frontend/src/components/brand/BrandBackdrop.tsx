import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { JoltLogo } from "./JoltLogo";

/**
 * Full-page frame for screens shown outside the app shell (public shares):
 * the blueprint grid, an amber glow, and the Jolt lockup on top.
 */
export function BrandBackdrop({
  children,
  center = false,
}: {
  children: ReactNode;
  center?: boolean;
}) {
  return (
    <div className="relative isolate flex min-h-screen flex-col overflow-hidden">
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 -z-10 bg-brand-grid mask-[radial-gradient(ellipse_at_top,black,transparent_70%)]"
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -top-48 left-1/2 -z-10 size-[36rem] -translate-x-1/2 rounded-full bg-brand/10 blur-3xl"
      />
      <div className="mx-auto flex w-full max-w-4xl items-center px-4 pt-6">
        <JoltLogo className="text-lg" />
      </div>
      <div
        className={cn(
          "flex-1 px-4",
          center ? "grid place-items-center pb-16" : "mx-auto grid w-full max-w-4xl content-start gap-4 py-8",
        )}
      >
        {children}
      </div>
    </div>
  );
}
