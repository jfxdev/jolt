// An explicit resume or discard may require a fresh signed binding. Only a
// server that explicitly reports the feature disabled may use legacy behavior.
export async function authorizeUploadIfEnabled(authorize: () => Promise<unknown>) {
  try {
    await authorize();
  } catch (error) {
    const failure = error as { status?: number; code?: string };
    if (failure?.status === 409 && failure.code === "signed_upload_unavailable") return;
    throw error;
  }
}
