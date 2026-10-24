import type { JobSummary } from "./types";

export function summarizeNetworkJobs(
  observations: (
    { value?: JobSummary; error?: string; restricted?: boolean } | undefined
  )[],
) {
  let active = 0,
    known = 0;
  let partial = false;
  for (const observation of observations) {
    if (observation?.value && !observation.restricted) {
      known++;
      for (const state of ["running", "pause_requested", "cancel_requested"])
        active += observation.value.counts[state] || 0;
    }
    if (!observation?.value || observation.error || observation.restricted)
      partial = true;
  }
  return {
    active: known || observations.length === 0 ? active : null,
    partial,
  };
}
