import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { BuildInfo } from "@/lib/types";

export function BuildVersion() {
  const [build, setBuild] = useState<BuildInfo | null>(null);

  useEffect(() => {
    let active = true;
    void api.about().then((value) => {
      if (active) setBuild(value);
    }).catch(() => {});
    return () => {
      active = false;
    };
  }, []);

  if (!build?.version || !build.commit || !build.build_date) return null;
  const revision = build.commit !== "unknown" ? ` · ${build.commit.slice(0, 8)}` : "";
  return (
    <p
      className="px-2 pb-2 text-xs text-muted-foreground"
      title={`Commit ${build.commit} · Build ${build.build_date}`}
      data-testid="build-version"
    >
      Jolt {build.version}{revision}
    </p>
  );
}
