/** Each slot runs one request; a group of requests never multiplies the cap. */
export async function runLimited(tasks: (() => Promise<void>)[], limit = 4) {
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, tasks.length) }, async () => {
      while (next < tasks.length) {
        const task = tasks[next++];
        await task();
      }
    }),
  );
}
