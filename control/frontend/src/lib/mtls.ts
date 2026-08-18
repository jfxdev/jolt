import type { MTLSRolloutPeer, MTLSState } from "./types";

/** The rollout entry for the currently-prepared certificate, if any. */
export function currentMTLSRollout(state: MTLSState | null) {
  const serial = state?.next?.serial;
  return serial ? state?.rollouts?.[serial] || null : null;
}

/** Flat list of peers participating in the current mTLS rollout. */
export function mtlsRolloutPeers(state: MTLSState | null): MTLSRolloutPeer[] {
  return Object.values(currentMTLSRollout(state)?.peers || {});
}
