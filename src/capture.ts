import { spawn } from "node:child_process";
import { createWriteStream, mkdirSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import process, { stderr, stdout } from "node:process";
import { ANSI } from "./constants.js";
import { parsePacketLine, selectCaptureFields } from "./packet.js";
import { SocketTracker } from "./socket-tracker.js";
import { color, heading } from "./terminal.js";
import type {
  CaptureInterface,
  NetworkProcess,
  Packet,
  PacketEndpoint,
} from "./types.js";

function formatEndpoint(value: PacketEndpoint): string {
  const host = value.ip || value.mac || "?";
  return value.port != null ? `${host}:${value.port}` : host;
}
function printPacket(packet: Packet): void {
  const direction = packet.direction === "outbound" ? "OUT" : "IN ";
  const directionColor =
    packet.direction === "outbound" ? ANSI.magenta : ANSI.cyan;
  const encryptionColor =
    packet.encryption.status === "encrypted"
      ? ANSI.green
      : packet.encryption.status === "likely-plaintext"
        ? ANSI.red
        : ANSI.yellow;
  stdout.write(
    `${[color(ANSI.dim, `#${packet.packetNumber ?? "?"}`), color(directionColor, direction), `${formatEndpoint(packet.source)} → ${formatEndpoint(packet.destination)}`, packet.transport?.protocol || "?", (packet.osi.layer7 as { protocol?: string } | undefined)?.protocol || "?", `${packet.frameLength ?? "?"}B`, color(encryptionColor, packet.encryption.status.toUpperCase())].join("  ")}\n`,
  );
  if (
    packet.encryption.status === "likely-plaintext" &&
    packet.payload?.readableStrings.length
  )
    stdout.write(
      `    ${color(ANSI.red, "Readable payload:")} ${packet.payload.readableStrings.slice(0, 3).join(" | ")}\n`,
    );
}
function safeFilePart(value: string): string {
  return String(value || "capture")
    .replace(/[^a-z0-9._-]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}
export async function captureProcessTraffic({
  interfaceInfo,
  processInfo,
}: {
  interfaceInfo: CaptureInterface;
  processInfo: NetworkProcess;
}): Promise<void> {
  const activeFields = await selectCaptureFields();
  const tracker = new SocketTracker(processInfo.pid);
  await tracker.start();
  mkdirSync("captures", { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const logPath = join(
    "captures",
    `${timestamp}-${safeFilePart(processInfo.displayName)}-${processInfo.pid}.ndjson`,
  );
  const log = createWriteStream(logPath, { flags: "a" });
  const args = [
    "-i",
    interfaceInfo.name,
    "-l",
    "-n",
    "-T",
    "fields",
    "-E",
    "separator=/t",
    "-E",
    "quote=d",
    "-E",
    "occurrence=f",
  ];
  for (const { field } of activeFields) args.push("-e", field);
  const tshark = spawn("tshark", args, { stdio: ["ignore", "pipe", "pipe"] });
  let matchedPackets = 0;
  let tsharkError = "";
  heading(
    `Viewing packets for ${processInfo.displayName} [PID ${processInfo.pid}]`,
  );
  stdout.write(
    `Interface: ${interfaceInfo.name}${interfaceInfo.description ? ` — ${interfaceInfo.description}` : ""}\nLog file: ${logPath}\nTracked sockets: ${tracker.size}\n`,
  );
  stdout.write(
    color(
      ANSI.dim,
      "Terminal: one line per packet. NDJSON log: full Layer 1–7 breakdown, headers, payload preview, and encryption assessment.\nPress Ctrl+C to stop.\n\n",
    ),
  );
  const lines = createInterface({ input: tshark.stdout!, crlfDelay: Infinity });
  lines.on("line", (line: string) => {
    if (!line.trim()) return;
    try {
      const packet = parsePacketLine(line, activeFields);
      const match = tracker.match(packet);
      if (!match) return;
      packet.process = {
        pid: processInfo.pid,
        name: processInfo.displayName,
        executable: processInfo.executable,
      };
      packet.interface = {
        name: interfaceInfo.name,
        description: interfaceInfo.description,
      };
      packet.direction = match.direction;
      packet.matchedSocket = match.socket;
      matchedPackets += 1;
      log.write(`${JSON.stringify(packet)}\n`);
      printPacket(packet);
    } catch (error: unknown) {
      stderr.write(
        `Packet parse warning: ${error instanceof Error ? error.message : String(error)}\n`,
      );
    }
  });
  tshark.stderr?.on("data", (chunk: Buffer) => {
    const message = chunk.toString();
    tsharkError += message;
    if (
      !message.includes("Capturing on") &&
      !message.includes("Packets captured") &&
      !message.toLowerCase().includes("running as user")
    )
      stderr.write(color(ANSI.dim, `[tshark] ${message}`));
  });
  const stop = (): void => {
    tracker.stop();
    if (!tshark.killed) tshark.kill("SIGINT");
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  await new Promise<void>((resolve, reject) => {
    tshark.on("error", reject);
    tshark.on("close", (code) => {
      tracker.stop();
      log.end();
      process.removeListener("SIGINT", stop);
      process.removeListener("SIGTERM", stop);
      stdout.write(
        `\nCaptured ${matchedPackets} packet(s) for ${processInfo.displayName}.\nSaved full records to ${logPath}.\n`,
      );
      if (code && code !== 0) {
        const hint = /permission|bpf|capture privileges/i.test(tsharkError)
          ? " TShark could not access the capture device. Install Wireshark's capture permissions or run the command with appropriate privileges."
          : "";
        reject(new Error(`TShark exited with code ${code}.${hint}`));
      } else resolve();
    });
  });
}
