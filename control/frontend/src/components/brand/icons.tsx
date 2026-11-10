import type { ReactNode, SVGProps } from "react";

// Jolt's own icon set, from docs/assets/icon-*.svg. The artwork is drawn on a
// 400 grid; the default stroke matches lucide's 2px-at-24px weight so the set
// mixes with lucide icons in the same menu.
type IconProps = SVGProps<SVGSVGElement>;

function brandIcon(name: string, body: ReactNode) {
  function BrandIcon({ strokeWidth = 30, ...props }: IconProps) {
    return (
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 400 400"
        width="24"
        height="24"
        fill="none"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
        {...props}
      >
        {body}
      </svg>
    );
  }
  BrandIcon.displayName = name;
  return BrandIcon;
}

export const NetworkIcon = brandIcon(
  "NetworkIcon",
  <>
    <circle cx="200" cy="92" r="31" />
    <circle cx="105" cy="278" r="31" />
    <circle cx="295" cy="278" r="31" />
    <path d="M185 122L121 249M215 122l64 127M136 278h128" />
  </>,
);

export const TransferIcon = brandIcon(
  "TransferIcon",
  <path d="M70 145h260m-62-62 62 62-62 62M330 255H70m62-62-62 62 62 62" />,
);

export const JobsIcon = brandIcon(
  "JobsIcon",
  <>
    <circle cx="200" cy="200" r="123" />
    <path d="m174 138 93 62-93 62z" />
  </>,
);

export const VolumesIcon = brandIcon(
  "VolumesIcon",
  <path d="M75 145l125-66 125 66-125 67zM75 200l125 67 125-67M75 256l125 67 125-67" />,
);

export const FilesIcon = brandIcon(
  "FilesIcon",
  <path d="M48 102h108l25 25h171v166H48z" />,
);

export const TrustIcon = brandIcon(
  "TrustIcon",
  <path d="M200 63 323 108v91q0 91-123 151Q77 290 77 199v-91zM142 199l41 42 80-88" />,
);

export const AccessIcon = brandIcon(
  "AccessIcon",
  <>
    <circle cx="155" cy="145" r="48" />
    <path d="M61 314q0-91 94-91t94 91M259 130q60 0 60 62M264 234q65 12 65 80" />
  </>,
);

export const MonitoringIcon = brandIcon(
  "MonitoringIcon",
  <path d="M42 207h73l40-83 68 160 42-77h93" />,
);

export const SettingsIcon = brandIcon(
  "SettingsIcon",
  <>
    <circle cx="200" cy="200" r="51" />
    <path d="M176 61h48l11 42 37 16 38-21 34 34-21 38 16 37 42 11v48l-42 11-16 37 21 38-34 34-38-21-37 16-11 42h-48l-11-42-37-16-38 21-34-34 21-38-16-37-42-11v-48l42-11 16-37-21-38 34-34 38 21 37-16z" />
  </>,
);
