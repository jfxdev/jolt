import assert from "node:assert/strict";
import { test } from "node:test";
import {
	chunkCount,
	OffsetMismatchError,
	uploadPercent,
	uploadResumable,
	UploadAbortedError,
	type UploadSession,
	type UploadTransport,
} from "../src/lib/resumable-upload.ts";

/** fakeServer accumulates bytes the way the node does: it writes only at the
 * offset it currently holds and rejects anything else with a 409. */
function fakeServer(options: { failAt?: number[]; failStatus?: number } = {}) {
	const state = {
		stored: [] as string[],
		offset: 0,
		completed: false,
		aborted: false,
		appends: 0,
		created: 0,
	};
	const failAt = new Set(options.failAt ?? []);
	const session = (overrides: Partial<UploadSession> = {}): UploadSession => ({
		upload_id: "upl_1",
		mount_id: "media",
		destination_path: "a.bin",
		size: 0,
		offset: state.offset,
		overwrite: false,
		chunk_size: 4,
		created_at: "",
		updated_at: "",
		expires_at: "",
		...overrides,
	});
	const transport: UploadTransport = {
		async create(input) {
			state.created += 1;
			return session({ size: input.size, destination_path: input.path });
		},
		async append(_id, chunk, offset, total) {
			state.appends += 1;
			if (failAt.has(state.appends)) {
				const error = new Error("boom") as Error & { status?: number };
				error.status = options.failStatus ?? 503;
				throw error;
			}
			if (offset !== state.offset) {
				const error = new Error("offset mismatch") as Error & {
					status?: number;
					details?: { offset: number };
				};
				error.status = 409;
				error.details = { offset: state.offset };
				throw error;
			}
			const text = await (chunk as unknown as { text(): Promise<string> }).text();
			state.stored.push(text);
			state.offset += text.length;
			return session({ size: total });
		},
		async complete() {
			state.completed = true;
			return {};
		},
		async abort() {
			state.aborted = true;
			return {};
		},
		async session() {
			return session();
		},
	};
	return { state, transport };
}

/** blobOf builds a Blob-like value with the slice/size/text surface the
 * uploader uses. Node's Blob is available, so this is just a helper. */
function blobOf(content: string): Blob {
	return new Blob([content]);
}

test("an upload is sent in chunks and completed once", async () => {
	const { state, transport } = fakeServer();
	await uploadResumable(transport, blobOf("abcdefghij"), "a.bin", false, {
		chunkSize: 4,
	});
	assert.deepEqual(state.stored, ["abcd", "efgh", "ij"]);
	assert.equal(state.offset, 10);
	assert.equal(state.completed, true);
	assert.equal(state.created, 1);
});

test("progress is reported monotonically up to the total", async () => {
	const { transport } = fakeServer();
	const seen: number[] = [];
	await uploadResumable(transport, blobOf("abcdefghij"), "a.bin", false, {
		chunkSize: 4,
		onProgress: ({ uploaded, total }) => {
			assert.equal(total, 10);
			seen.push(uploaded);
		},
	});
	assert.deepEqual(seen, [0, 4, 8, 10]);
});

test("a transient failure is retried without resending completed chunks", async () => {
	// The second append fails once with a 503, then succeeds.
	const { state, transport } = fakeServer({ failAt: [2] });
	const waits: number[] = [];
	await uploadResumable(transport, blobOf("abcdefgh"), "a.bin", false, {
		chunkSize: 4,
		sleep: async (ms) => {
			waits.push(ms);
		},
	});
	assert.deepEqual(state.stored, ["abcd", "efgh"]);
	assert.equal(state.completed, true);
	// One retry means exactly one backoff wait.
	assert.equal(waits.length, 1);
});

test("retries stop at maxAttempts and surface the error", async () => {
	const { state, transport } = fakeServer({ failAt: [1, 2, 3, 4, 5, 6] });
	await assert.rejects(
		uploadResumable(transport, blobOf("abcd"), "a.bin", false, {
			chunkSize: 4,
			maxAttempts: 3,
			sleep: async () => {},
		}),
		/boom/,
	);
	assert.equal(state.appends, 3);
	assert.equal(state.completed, false);
});

test("a permanent rejection is not retried", async () => {
	// A 403 will never succeed, so burning retries on it only wastes time.
	const { state, transport } = fakeServer({ failAt: [1], failStatus: 403 });
	await assert.rejects(
		uploadResumable(transport, blobOf("abcd"), "a.bin", false, {
			chunkSize: 4,
			sleep: async () => {},
		}),
	);
	assert.equal(state.appends, 1);
});

test("an offset mismatch resumes from the offset the server reports", async () => {
	const { state, transport } = fakeServer();
	// Simulate a client that believes nothing was sent while the server already
	// holds four bytes, as happens when a response is lost in flight.
	state.offset = 4;
	state.stored.push("abcd");
	await uploadResumable(transport, blobOf("abcdefgh"), "a.bin", false, {
		chunkSize: 4,
		sleep: async () => {},
	});
	// The already-stored chunk is not duplicated.
	assert.deepEqual(state.stored, ["abcd", "efgh"]);
	assert.equal(state.offset, 8);
	assert.equal(state.completed, true);
});

test("an existing session is resumed instead of reopened", async () => {
	const { state, transport } = fakeServer();
	state.offset = 4;
	state.stored.push("abcd");
	await uploadResumable(transport, blobOf("abcdefgh"), "a.bin", false, {
		chunkSize: 4,
		resumeFrom: {
			upload_id: "upl_1",
			mount_id: "media",
			destination_path: "a.bin",
			size: 8,
			offset: 4,
			overwrite: false,
			chunk_size: 4,
			created_at: "",
			updated_at: "",
			expires_at: "",
		},
	});
	assert.equal(state.created, 0, "resuming must not open a new session");
	assert.deepEqual(state.stored, ["abcd", "efgh"]);
});

test("an aborted upload stops before sending anything else", async () => {
	const { state, transport } = fakeServer();
	const controller = new AbortController();
	controller.abort();
	await assert.rejects(
		uploadResumable(transport, blobOf("abcd"), "a.bin", false, {
			chunkSize: 4,
			signal: controller.signal,
		}),
		UploadAbortedError,
	);
	assert.equal(state.created, 0);
	assert.equal(state.appends, 0);
});

test("an abort mid-upload leaves earlier chunks in place", async () => {
	const { state, transport } = fakeServer();
	const controller = new AbortController();
	await assert.rejects(
		uploadResumable(transport, blobOf("abcdefghij"), "a.bin", false, {
			chunkSize: 4,
			onProgress: ({ uploaded }) => {
				if (uploaded >= 4) controller.abort();
			},
			signal: controller.signal,
		}),
		UploadAbortedError,
	);
	assert.deepEqual(state.stored, ["abcd"]);
	assert.equal(state.completed, false, "an aborted upload is never published");
});

test("an empty file is created and completed without any chunk", async () => {
	const { state, transport } = fakeServer();
	await uploadResumable(transport, blobOf(""), "empty.bin", false, {
		chunkSize: 4,
	});
	assert.equal(state.appends, 0);
	assert.equal(state.completed, true);
});

test("a file smaller than one chunk is sent in a single request", async () => {
	const { state, transport } = fakeServer();
	await uploadResumable(transport, blobOf("ab"), "a.bin", false, {
		chunkSize: 1024,
	});
	assert.equal(state.appends, 1);
	assert.deepEqual(state.stored, ["ab"]);
});

test("chunkCount and uploadPercent stay in range", () => {
	assert.equal(chunkCount(0, 10), 0);
	assert.equal(chunkCount(10, 10), 1);
	assert.equal(chunkCount(11, 10), 2);
	assert.equal(uploadPercent(0, 0), 0);
	assert.equal(uploadPercent(5, 0), 100, "an empty total must not yield NaN");
	assert.equal(uploadPercent(5, 10), 50);
	assert.equal(uploadPercent(50, 10), 100, "progress is clamped at 100");
	assert.equal(uploadPercent(-5, 10), 0);
});

test("OffsetMismatchError carries the server offset", () => {
	const error = new OffsetMismatchError(42);
	assert.equal(error.offset, 42);
	assert.equal(error.name, "OffsetMismatchError");
});


test("the server chunk limit overrides a larger client chunk size", async () => {
 const {transport,state}=fakeServer();
 await uploadResumable(transport,new Blob(["abcdefghij"]),"a.bin",false,{chunkSize:8});
 assert.deepEqual(state.stored,["abcd","efgh","ij"]);
 assert.equal(state.completed,true);
});
