import fs from "node:fs/promises";
import path from "node:path";

export const SUPPORTED_EVIDENCE_TYPES = ["PDF", "DOC", "DOCX", "TXT", "JPG", "JPEG", "PNG", "TIFF", "BMP", "MP4", "MOV", "AVI", "MKV", "MP3", "WAV", "E01", "RAW", "LOG", "CSV", "JSON", "XML"] as const;
export type SupportedEvidenceType = (typeof SUPPORTED_EVIDENCE_TYPES)[number];

const extensionType: Record<string, SupportedEvidenceType> = {
  ".pdf": "PDF", ".doc": "DOC", ".docx": "DOCX", ".txt": "TXT", ".jpg": "JPG", ".jpeg": "JPEG", ".png": "PNG", ".tif": "TIFF", ".tiff": "TIFF", ".bmp": "BMP", ".mp4": "MP4", ".mov": "MOV", ".avi": "AVI", ".mkv": "MKV", ".mp3": "MP3", ".wav": "WAV", ".e01": "E01", ".ex01": "E01", ".dd": "RAW", ".img": "RAW", ".raw": "RAW", ".dmg": "RAW", ".log": "LOG", ".csv": "CSV", ".json": "JSON", ".xml": "XML"
};

function has(bytes: Buffer, ...values: number[]): boolean { return values.every((value, index) => bytes[index] === value); }
function ascii(bytes: Buffer, start: number, value: string): boolean { return bytes.subarray(start, start + value.length).toString("ascii") === value; }
function printableText(bytes: Buffer): boolean { if (!bytes.length || bytes.includes(0)) return false; const sample = bytes.toString("utf8"); return !sample.includes("�") && [...sample].filter((char) => char === "\n" || char === "\r" || char === "\t" || char >= " ").length / sample.length > 0.95; }

export async function detectEvidenceType(filePath: string, originalName: string): Promise<SupportedEvidenceType> {
  const extension = path.extname(originalName).toLowerCase(); const declared = extensionType[extension]; const handle = await fs.open(filePath, "r"); const buffer = Buffer.alloc(16384); let bytes: Buffer;
  try { const result = await handle.read(buffer, 0, buffer.length, 0); bytes = buffer.subarray(0, result.bytesRead); } finally { await handle.close(); }
  if (ascii(bytes, 0, "%PDF-")) return "PDF";
  if (has(bytes, 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1)) return "DOC";
  if (has(bytes, 0x50, 0x4b, 0x03, 0x04) && [".docx"].includes(extension)) return "DOCX";
  if (has(bytes, 0xff, 0xd8, 0xff)) return extension === ".jpeg" ? "JPEG" : "JPG";
  if (has(bytes, 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)) return "PNG";
  if (has(bytes, 0x49, 0x49, 0x2a, 0x00) || has(bytes, 0x4d, 0x4d, 0x00, 0x2a)) return "TIFF";
  if (ascii(bytes, 0, "BM")) return "BMP";
  if (ascii(bytes, 4, "ftyp") && [".mp4", ".mov"].includes(extension)) return extension === ".mov" ? "MOV" : "MP4";
  if (ascii(bytes, 0, "RIFF") && ascii(bytes, 8, "AVI ")) return "AVI";
  if (has(bytes, 0x1a, 0x45, 0xdf, 0xa3)) return "MKV";
  if (ascii(bytes, 0, "ID3") || (bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0)) return "MP3";
  if (ascii(bytes, 0, "RIFF") && ascii(bytes, 8, "WAVE")) return "WAV";
  if (has(bytes, 0x45, 0x56, 0x46)) return "E01";
  if (printableText(bytes) && [".txt", ".log", ".csv", ".json", ".xml"].includes(extension)) return declared;
  if (declared === "RAW") return "RAW"; // Raw images have no universal magic; extension + size policy is the available signal.
  throw new Error("File content does not match a supported evidence format");
}

export async function validateEvidenceFile(filePath: string, originalName: string, maxBytes: number): Promise<SupportedEvidenceType> {
  const stat = await fs.stat(filePath); if (!stat.isFile()) throw new Error("Uploaded evidence is not a regular file"); if (stat.size > maxBytes) throw new Error("Uploaded file exceeds the configured size limit"); return detectEvidenceType(filePath, originalName);
}
