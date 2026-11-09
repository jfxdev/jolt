import { useId, type SVGProps } from "react";
import { cn } from "@/lib/utils";

// Paths are the 400×400 artwork from docs/assets/jolt-transparent.svg, cropped
// to the folder's bounds so the mark sits flush in its box.
const FOLDER =
  "M 72 151 L 72 110 Q 72 91 91 91 L 169 91 Q 181 91 189 101 L 209 123 Q 215 130 229 130 L 320 130 Q 342 130 342 152 L 342 276 Q 342 298 320 298 L 94 298 Q 72 298 72 276 Z";
const BOLT = "M 226 151 L 163 221 L 205 221 L 175 277 L 254 195 L 209 195 Z";

type MarkProps = SVGProps<SVGSVGElement> & {
  /** "gradient" is the primary mark; "mono" follows `currentColor`. */
  tone?: "gradient" | "mono";
  /** Soft amber halo behind the folder outline, for large hero placements. */
  glow?: boolean;
};

/** The Jolt mark: a folder outline charged with a lightning bolt. */
export function JoltMark({ tone = "gradient", glow = false, className, ...props }: MarkProps) {
  const id = useId().replace(/:/g, "");
  const paint = tone === "gradient" ? `url(#${id}-amber)` : "currentColor";

  return (
    <svg
      viewBox="58 77 298 235"
      fill="none"
      aria-hidden="true"
      className={cn("shrink-0", className)}
      {...props}
    >
      <defs>
        <linearGradient id={`${id}-amber`} x1="0" y1="0" x2="1" y2="1">
          <stop stopColor="#FACC15" />
          <stop offset="1" stopColor="#F97316" />
        </linearGradient>
        {glow && (
          <filter id={`${id}-glow`} x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="7" />
          </filter>
        )}
      </defs>
      {glow && (
        <path
          d={FOLDER}
          stroke={paint}
          strokeWidth="17"
          strokeLinejoin="round"
          filter={`url(#${id}-glow)`}
          opacity=".7"
        />
      )}
      <path
        d={FOLDER}
        stroke={paint}
        strokeWidth="18"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      <path d={BOLT} fill={paint} strokeLinejoin="round" />
    </svg>
  );
}

/** Mark plus the "Jolt" wordmark, the horizontal lockup. */
export function JoltLogo({
  className,
  markClassName,
  label = "Jolt",
}: {
  className?: string;
  markClassName?: string;
  label?: string;
}) {
  return (
    <span className={cn("inline-flex items-center gap-2.5", className)}>
      <JoltMark className={cn("h-[1.1em] w-auto", markClassName)} />
      <span className="font-bold tracking-tight">{label}</span>
    </span>
  );
}
