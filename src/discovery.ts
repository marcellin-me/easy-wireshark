import { basename } from "node:path";
import { runCommand } from "./command.js";
import type {
  CaptureInterface,
  Endpoint,
  NetworkProcess,
  ProcessSummary,
  Protocol,
  SocketRecord,
} from "./types.js";

export async function listCaptureInterfaces(): Promise<CaptureInterface[]> {
  const { stdout } = await runCommand("tshark", ["-D"]);
  return stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .flatMap((line) => {
      const match = line.match(/^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?$/);
      return match
        ? [
            {
              number: Number(match[1]),
              name: match[2],
              description: match[3] || "",
            },
          ]
        : [];
    });
}
export async function getInterfaceAddresses(
  interfaceName: string,
): Promise<Set<string>> {
  try {
    const { stdout } = await runCommand("ifconfig", [interfaceName]);
    const addresses = new Set<string>();
    for (const line of stdout.split(/\r?\n/)) {
      const address = line.match(/^\s*inet6?\s+([^\s]+)/)?.[1];
      if (address) addresses.add(normalizeHost(address));
    }
    return addresses;
  } catch {
    return new Set();
  }
}
async function getProcessExecutableMap(): Promise<Map<number, string>> {
  const executables = new Map<number, string>();
  try {
    const { stdout } = await runCommand("ps", ["-axo", "pid=,comm="]);
    for (const line of stdout.split(/\r?\n/)) {
      const match = line.match(/^\s*(\d+)\s+(.+)$/);
      if (match) executables.set(Number(match[1]), match[2].trim());
    }
  } catch {
    /* lsof command is the fallback */
  }
  return executables;
}
type UnfinishedSocket = Partial<SocketRecord>;
type UnfinishedProcess = {
  pid: number;
  command: string;
  sockets: SocketRecord[];
};
export function parseLsofFieldOutput(output: string): NetworkProcess[] {
  const processes = new Map<number, NetworkProcess>();
  let currentProcess: UnfinishedProcess | null = null;
  let currentSocket: UnfinishedSocket | null = null;
  const commitSocket = (): void => {
    if (!currentProcess || !currentSocket?.protocol || !currentSocket.name)
      return;
    const parsed = parseSocketName(currentSocket.name);
    if (!parsed) return;
    currentProcess.sockets.push({
      ...parsed,
      fileDescriptor: currentSocket.fileDescriptor,
      state: currentSocket.state || "",
      protocol: currentSocket.protocol.toUpperCase() as Protocol,
    });
  };
  const commitProcess = (): void => {
    commitSocket();
    currentSocket = null;
    if (!currentProcess || !Number.isInteger(currentProcess.pid)) return;
    const existing = processes.get(currentProcess.pid);
    if (existing) {
      existing.sockets.push(...currentProcess.sockets);
      if (!existing.command && currentProcess.command)
        existing.command = currentProcess.command;
    } else
      processes.set(currentProcess.pid, {
        ...currentProcess,
        executable: "",
        displayName: "",
      });
  };
  for (const rawLine of output.split(/\r?\n/)) {
    if (!rawLine) continue;
    const field = rawLine[0];
    const value = rawLine.slice(1);
    switch (field) {
      case "p":
        commitProcess();
        currentProcess = { pid: Number(value), command: "", sockets: [] };
        currentSocket = null;
        break;
      case "c":
        if (currentProcess) currentProcess.command = value;
        break;
      case "f":
        commitSocket();
        currentSocket = { fileDescriptor: value, state: "" };
        break;
      case "P":
        currentSocket ??= { state: "" };
        currentSocket.protocol = value as Protocol;
        break;
      case "n":
        currentSocket ??= { state: "" };
        currentSocket.name = value;
        break;
      case "T":
        currentSocket ??= { state: "" };
        if (value.startsWith("ST=")) currentSocket.state = value.slice(3);
        break;
    }
  }
  commitProcess();
  return [...processes.values()].filter(
    (process) => process.sockets.length > 0,
  );
}
export async function listNetworkProcesses(): Promise<NetworkProcess[]> {
  const { stdout } = await runCommand("lsof", ["-nP", "-i", "-FpcfPnT"]);
  const processes = parseLsofFieldOutput(stdout);
  const executables = await getProcessExecutableMap();
  return processes.map((process) => ({
    ...process,
    executable: executables.get(process.pid) || "",
    displayName: deriveDisplayName(
      executables.get(process.pid) || "",
      process.command,
    ),
  }));
}
export async function listSocketsForPid(pid: number): Promise<SocketRecord[]> {
  try {
    const { stdout } = await runCommand("lsof", [
      "-nP",
      "-a",
      "-p",
      String(pid),
      "-i",
      "-FpcfPnT",
    ]);
    return (
      parseLsofFieldOutput(stdout).find((process) => process.pid === pid)
        ?.sockets || []
    );
  } catch {
    return [];
  }
}
export function deriveDisplayName(
  executable: string,
  fallback: string,
): string {
  return (
    executable.match(/\/([^/]+)\.app\/Contents\/MacOS\//)?.[1] ||
    (executable ? basename(executable) : fallback || "Unknown process")
  );
}
export function parseSocketName(
  name: string,
): { local: Endpoint; remote: Endpoint | null } | null {
  const cleaned = name.replace(/\s+\([^)]*\)\s*$/, "").trim();
  const index = cleaned.indexOf("->");
  const local = parseEndpoint(index >= 0 ? cleaned.slice(0, index) : cleaned);
  return local
    ? {
        local,
        remote: index >= 0 ? parseEndpoint(cleaned.slice(index + 2)) : null,
      }
    : null;
}
export function parseEndpoint(value: string): Endpoint | null {
  const text = value.trim();
  if (!text) return null;
  if (text.startsWith("[")) {
    const closing = text.lastIndexOf("]:");
    return closing < 0
      ? null
      : endpoint(text.slice(1, closing), text.slice(closing + 2));
  }
  const colon = text.lastIndexOf(":");
  return colon < 0
    ? null
    : endpoint(text.slice(0, colon), text.slice(colon + 1));
}
function endpoint(host: string, portText: string): Endpoint | null {
  const port = Number(portText);
  return Number.isInteger(port) ? { host: normalizeHost(host), port } : null;
}
export function normalizeHost(host: string | undefined): string {
  return String(host || "")
    .trim()
    .replace(/^\[/, "")
    .replace(/\]$/, "")
    .replace(/%.+$/, "")
    .toLowerCase();
}
export function socketBelongsToInterface(
  socket: SocketRecord,
  addresses: Set<string>,
  interfaceName: string,
): boolean {
  const host = normalizeHost(socket.local.host);
  return (
    !host ||
    host === "*" ||
    addresses.has(host) ||
    ((host === "127.0.0.1" || host === "::1") && interfaceName === "lo0")
  );
}
export function summarizeProcess(
  process: NetworkProcess,
  addresses: Set<string>,
  interfaceName: string,
): ProcessSummary {
  const sockets = process.sockets.filter((socket) =>
    socketBelongsToInterface(socket, addresses, interfaceName),
  );
  return {
    ...process,
    sockets,
    established: sockets.filter((socket) => socket.state === "ESTABLISHED")
      .length,
    listeners: sockets.filter((socket) => socket.state === "LISTEN").length,
    tcp: sockets.filter((socket) => socket.protocol === "TCP").length,
    udp: sockets.filter((socket) => socket.protocol === "UDP").length,
  };
}
