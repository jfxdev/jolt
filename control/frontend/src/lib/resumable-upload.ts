import type { UploadSession } from "./types";

/** UploadTransport is the small slice of the API the uploader needs. Injecting
 * it keeps the resume and retry logic testable without a network. */
export interface UploadTransport {
	create(input: {
		path: string;
		size: number;
		overwrite: boolean;
	}): Promise<UploadSession>;
	append(
		uploadId: string,
		chunk: Blob,
		offset: number,
		total: number,
	): Promise<UploadSession>;
	complete(uploadId: string): Promise<unknown>;
	abort(uploadId: string): Promise<unknown>;
	session?(uploadId: string): Promise<UploadSession>;
}

export interface UploadProgress {
	uploaded: number;
	total: number;
	/** attempt counts retries of the current chunk, so the UI can say
	 * "retrying" instead of appearing stuck. */
	attempt: number;
}

export interface UploadOptions {
	chunkSize?: number;
	maxAttempts?: number;
	/** backoffMs returns how long to wait before retrying an attempt. It is
	 * injectable so tests do not actually sleep. */
	backoffMs?: (attempt: number) => number;
	sleep?: (ms: number) => Promise<void>;
	onProgress?: (progress: UploadProgress) => void;
	signal?: AbortSignal;
	/** resumeFrom continues an existing session instead of opening a new one. */
	resumeFrom?: UploadSession;
}

/** OffsetMismatchError carries the offset the server actually holds, which is
 * what lets an interrupted upload resume instead of restarting. */
export class OffsetMismatchError extends Error {
	readonly offset: number;
	constructor(offset: number) {
		super(`upload is at ${offset} bytes`);
		this.name = "OffsetMismatchError";
		this.offset = offset;
	}
}

export class UploadAbortedError extends Error {
	constructor() {
		super("upload aborted");
		this.name = "UploadAbortedError";
	}
}

export const DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024;

function defaultBackoff(attempt: number) {
	// 0.5s, 1s, 2s, 4s… capped so a long outage does not stall forever.
	return Math.min(500 * 2 ** (attempt - 1), 15_000);
}

const defaultSleep = (ms: number) =>
	new Promise<void>((resolve) => setTimeout(resolve, ms));

/** isRetryable distinguishes a transient failure from a rejection that will
 * never succeed. Retrying a 403 or a 409 conflict just burns time. */
function isRetryable(error: unknown) {
	const status = (error as { status?: number })?.status;
	if (status === undefined) return true; // a network error has no status
	if (status === 408 || status === 429) return true;
	return status >= 500;
}

/**
 * uploadResumable sends a file in chunks, surviving a dropped connection by
 * resuming from the offset the server reports rather than starting over.
 *
 * The server is the authority on the offset: when it answers an append with a
 * mismatch, the uploader seeks to the reported offset and continues from there.
 */
export async function uploadResumable(
	transport: UploadTransport,
	file: Blob,
	path: string,
	overwrite: boolean,
	options: UploadOptions = {},
): Promise<UploadSession> {
	const requestedChunkSize = Math.max(1, options.chunkSize ?? DEFAULT_CHUNK_SIZE);
	const maxAttempts = Math.max(1, options.maxAttempts ?? 5);
	const backoff = options.backoffMs ?? defaultBackoff;
	const sleep = options.sleep ?? defaultSleep;
	const total = file.size;

	const throwIfAborted = () => {
		if (options.signal?.aborted) throw new UploadAbortedError();
	};
	throwIfAborted();

	let session =
		options.resumeFrom ??
		(await transport.create({ path, size: total, overwrite }));
	const chunkSize = Math.min(requestedChunkSize, Math.max(1, session.chunk_size || requestedChunkSize));
	let offset = session.offset ?? 0;
	options.onProgress?.({ uploaded: offset, total, attempt: 0 });

	while (offset < total) {
		throwIfAborted();
		const chunk = file.slice(offset, Math.min(offset + chunkSize, total));
		let attempt = 0;
		for (;;) {
			attempt += 1;
			try {
				session = await transport.append(
					session.upload_id,
					chunk,
					offset,
					total,
				);
				offset = session.offset ?? offset + chunk.size;
				options.onProgress?.({ uploaded: offset, total, attempt });
				break;
			} catch (error) {
				throwIfAborted();
				const status = (error as { status?: number })?.status;
				if (status === 409) {
					// The server holds a different offset; trust it and resume
					// from there rather than retrying the same range.
					const reported = await resolveOffset(
						transport,
						session.upload_id,
						error,
					);
					if (reported === null) throw error;
					offset = reported;
					options.onProgress?.({ uploaded: offset, total, attempt });
					break;
				}
				if (attempt >= maxAttempts || !isRetryable(error)) throw error;
				await sleep(backoff(attempt));
			}
		}
	}

	throwIfAborted();
	await transport.complete(session.upload_id);
	return { ...session, offset: total };
}

/** resolveOffset reads the authoritative offset out of a 409, falling back to
 * asking the server for the session when the response carried no offset. */
async function resolveOffset(
	transport: UploadTransport,
	uploadId: string,
	error: unknown,
): Promise<number | null> {
	const detail = (error as { details?: { offset?: number } })?.details;
	if (typeof detail?.offset === "number") return detail.offset;
	const offset = (error as { offset?: number })?.offset;
	if (typeof offset === "number") return offset;
	if (!transport.session) return null;
	try {
		const session = await transport.session(uploadId);
		return session.offset ?? null;
	} catch {
		return null;
	}
}

/** chunkCount reports how many requests an upload will take, for the UI. */
export function chunkCount(size: number, chunkSize = DEFAULT_CHUNK_SIZE) {
	if (size <= 0) return 0;
	return Math.ceil(size / Math.max(1, chunkSize));
}

/** uploadPercent clamps progress to 0–100 and never reports NaN for an empty
 * file, which would render as a broken progress bar. */
export function uploadPercent(uploaded: number, total: number) {
	if (total <= 0) return uploaded > 0 ? 100 : 0;
	return Math.max(0, Math.min(100, Math.round((uploaded / total) * 100)));
}
