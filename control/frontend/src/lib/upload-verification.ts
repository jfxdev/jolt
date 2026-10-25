import type { UploadSession, UploadVerification } from "./types";

/** Verify every durable byte without reading the whole file into browser RAM. */
export async function verifyUploadSource(
  file: Blob,
  session: UploadSession,
  page: (after: number) => Promise<UploadVerification>,
  signal?: AbortSignal,
) {
  if (file.size !== session.size)
    throw new Error("O tamanho do arquivo não corresponde ao envio pendente.");
  let after = 0;
  do {
    if (signal?.aborted) throw new Error("Verificação cancelada.");
    const result = await page(after);
    if (result.offset !== session.offset || result.offset > file.size)
      throw new Error(
        "O envio mudou durante a verificação. Atualize e tente novamente.",
      );
    let verified = after;
    for (const block of result.blocks) {
      if (signal?.aborted) throw new Error("Verificação cancelada.");
      if (
        block.offset !== verified ||
        block.size <= 0 ||
        block.size > 8 * 1024 * 1024 ||
        block.offset + block.size > result.offset
      )
        throw new Error("O node retornou uma verificação inválida.");
      if (!globalThis.crypto?.subtle)
        throw new Error(
          "A verificação exige uma conexão HTTPS ou acesso local.",
        );
      const hash = await crypto.subtle.digest(
        "SHA-256",
        await file.slice(block.offset, block.offset + block.size).arrayBuffer(),
      );
      const hex = Array.from(new Uint8Array(hash), (value) =>
        value.toString(16).padStart(2, "0"),
      ).join("");
      if (hex !== block.sha256)
        throw new Error(
          "O conteúdo do arquivo é diferente do envio pendente. Nenhum byte foi enviado.",
        );
      verified += block.size;
    }
    if (
      (result.next_after &&
        (result.next_after !== verified || result.next_after <= after)) ||
      (!result.next_after && verified !== result.offset)
    )
      throw new Error("A verificação do conteúdo está incompleta.");
    after = result.next_after;
  } while (after);
}
