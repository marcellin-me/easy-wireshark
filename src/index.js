#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createWriteStream, mkdirSync } from "node:fs";
import { basename, join } from "node:path";
import { createInterface } from "node:readline";
import { createInterface as createPromiseInterface } from "node:readline/promises";
import { stdin, stdout, stderr } from "node:process";

const APP_NAME = "Packet Scope";
const SOCKET_REFRESH_MS = 350;
const SOCKET_GRACE_MS = 5_000;
const MAX_ASCII_PREVIEW = 160;

const FIELD_SPECS = [
  ["number", "frame.number"],
  ["timeEpoch", "frame.time_epoch"],
  ["frameLength", "frame.len"],
  ["capturedLength", "frame.cap_len"],
  ["encapsulation", "frame.encap_type"],
  ["protocolStack", "frame.protocols"],
  ["ethSource", "eth.src"],
  ["ethDestination", "eth.dst"],
  ["wlanSource", "wlan.sa"],
  ["wlanDestination", "wlan.da"],
  ["ipv4Source", "ip.src"],
  ["ipv4Destination", "ip.dst"],
  ["ipv4Ttl", "ip.ttl"],
  ["ipv4Protocol", "ip.proto"],
  ["ipv6Source", "ipv6.src"],
  ["ipv6Destination", "ipv6.dst"],
  ["ipv6HopLimit", "ipv6.hlim"],
  ["ipv6NextHeader", "ipv6.nxt"],
  ["tcpSourcePort", "tcp.srcport"],
  ["tcpDestinationPort", "tcp.dstport"],
  ["tcpFlags", "tcp.flags"],
  ["tcpSequence", "tcp.seq"],
  ["tcpAcknowledgement", "tcp.ack"],
  ["tcpStream", "tcp.stream"],
  ["tcpPayload", "tcp.payload"],
  ["udpSourcePort", "udp.srcport"],
  ["udpDestinationPort", "udp.dstport"],
  ["udpLength", "udp.length"],
  ["udpStream", "udp.stream"],
  ["udpPayload", "udp.payload"],
  ["tlsRecordType", "tls.record.content_type"],
  ["tlsHandshakeType", "tls.handshake.type"],
  ["tlsVersion", "tls.record.version"],
  ["httpMethod", "http.request.method"],
  ["httpUri", "http.request.uri"],
  ["httpHost", "http.host"],
  ["httpContentType", "http.content_type"],
  ["dnsQuery", "dns.qry.name"],
  ["dataPayload", "data.data"],
  ["columnProtocol", "_ws.col.Protocol"],
  ["columnInfo", "_ws.col.Info"]
];

const ANSI = {
  reset: "\u001b[0m",
  bold: "\u001b[1m",
  dim: "\u001b[2m",
  cyan: "\u001b[36m",
  green: "\u001b[32m",
  yellow: "\u001b[33m",
  red: "\u001b[31m",
  magenta: "\u001b[35m"
};

function color(code, text) {
  return stdout.isTTY ? `${code}${text}${ANSI.reset}` : text;
}

function heading(text) {
  stdout.write(`\n${color(ANSI.bold + ANSI.cyan, text)}\n`);
}

function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"],
      ...options
    });

    let out = "";
    let err = "";

    child.stdout?.on("data", (chunk) => {
      out += chunk.toString();
    });

    child.stderr?.on("data", (chunk) => {
      err += chunk.toString();
    });

    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve({ stdout: out, stderr: err });
      } else {
        const error = new Error(
          `${command} exited with code ${code}${err ? `: ${err.trim()}` : ""}`
        );
        error.exitCode = code;
        error.stdout = out;
        error.stderr = err;
        reject(error);
      }
    });
  });
}

async function commandExists(command) {
  try {
    await runCommand("/usr/bin/which", [command]);
    return true;
  } catch {
    return false;
  }
}

async function verifyRequirements() {
  const missing = [];

  if (!(await commandExists("tshark"))) missing.push("tshark");
  if (!(await commandExists("lsof"))) missing.push("lsof");
  if (!(await commandExists("ifconfig"))) missing.push("ifconfig");

  if (missing.length > 0) {
    throw new Error(
      `Missing required command(s): ${missing.join(", ")}. ` +
        "Install Wireshark/TShark and make sure the commands are on PATH."
    );
  }
}

async function listCaptureInterfaces() {
  const { stdout: output } = await runCommand("tshark", ["-D"]);

  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const match = line.match(/^(\d+)\.\s+(\S+)(?:\s+\((.*)\))?$/);
      if (!match) return null;

      return {
        number: Number(match[1]),
        name: match[2],
        description: match[3] || ""
      };
    })
    .filter(Boolean);
}

async function getInterfaceAddresses(interfaceName) {
  try {
    const { stdout: output } = await runCommand("ifconfig", [interfaceName]);
    const addresses = new Set();

    for (const line of output.split(/\r?\n/)) {
      const ipv4 = line.match(/^\s*inet\s+([^\s]+)/);
      if (ipv4) addresses.add(normalizeHost(ipv4[1]));

      const ipv6 = line.match(/^\s*inet6\s+([^\s]+)/);
      if (ipv6) addresses.add(normalizeHost(ipv6[1]));
    }

    return addresses;
  } catch {
    return new Set();
  }
}

async function getProcessExecutableMap() {
  const map = new Map();

  try {
    const { stdout: output } = await runCommand("ps", ["-axo", "pid=,comm="]);

    for (const line of output.split(/\r?\n/)) {
      const match = line.match(/^\s*(\d+)\s+(.+)$/);
      if (!match) continue;
      map.set(Number(match[1]), match[2].trim());
    }
  } catch {
    // lsof's command name remains available as a fallback.
  }

  return map;
}

function parseLsofFieldOutput(output) {
  const processes = new Map();
  let currentProcess = null;
  let currentSocket = null;

  const commitSocket = () => {
    if (!currentProcess || !currentSocket) return;
    if (!currentSocket.protocol || !currentSocket.name) return;

    const parsed = parseSocketName(currentSocket.name);
    if (!parsed) return;

    currentProcess.sockets.push({
      ...currentSocket,
      ...parsed,
      protocol: currentSocket.protocol.toUpperCase()
    });
  };

  const commitProcess = () => {
    commitSocket();
    currentSocket = null;

    if (!currentProcess || !Number.isInteger(currentProcess.pid)) return;

    const existing = processes.get(currentProcess.pid);
    if (existing) {
      existing.sockets.push(...currentProcess.sockets);
      if (!existing.command && currentProcess.command) {
        existing.command = currentProcess.command;
      }
    } else {
      processes.set(currentProcess.pid, currentProcess);
    }
  };

  for (const rawLine of output.split(/\r?\n/)) {
    if (!rawLine) continue;

    const field = rawLine[0];
    const value = rawLine.slice(1);

    switch (field) {
      case "p":
        commitProcess();
        currentProcess = {
          pid: Number(value),
          command: "",
          sockets: []
        };
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
        if (!currentSocket) currentSocket = { state: "" };
        currentSocket.protocol = value;
        break;

      case "n":
        if (!currentSocket) currentSocket = { state: "" };
        currentSocket.name = value;
        break;

      case "T":
        if (!currentSocket) currentSocket = { state: "" };
        if (value.startsWith("ST=")) currentSocket.state = value.slice(3);
        break;

      default:
        break;
    }
  }

  commitProcess();
  return [...processes.values()].filter((process) => process.sockets.length > 0);
}

async function listNetworkProcesses() {
  const { stdout: output } = await runCommand("lsof", [
    "-nP",
    "-i",
    "-FpcfPnT"
  ]);

  const processes = parseLsofFieldOutput(output);
  const executables = await getProcessExecutableMap();

  for (const process of processes) {
    process.executable = executables.get(process.pid) || "";
    process.displayName = deriveDisplayName(process.executable, process.command);
  }

  return processes;
}

async function listSocketsForPid(pid) {
  try {
    const { stdout: output } = await runCommand("lsof", [
      "-nP",
      "-a",
      "-p",
      String(pid),
      "-i",
      "-FpcfPnT"
    ]);

    const processes = parseLsofFieldOutput(output);
    return processes.find((process) => process.pid === pid)?.sockets || [];
  } catch {
    return [];
  }
}

function deriveDisplayName(executable, fallback) {
  const appBundle = executable.match(/\/([^/]+)\.app\/Contents\/MacOS\//);
  if (appBundle) return appBundle[1];
  if (executable) return basename(executable);
  return fallback || "Unknown process";
}

function parseSocketName(name) {
  const cleaned = name.replace(/\s+\([^)]*\)\s*$/, "").trim();
  const arrowIndex = cleaned.indexOf("->");

  const localText = arrowIndex >= 0 ? cleaned.slice(0, arrowIndex) : cleaned;
  const remoteText = arrowIndex >= 0 ? cleaned.slice(arrowIndex + 2) : "";

  const local = parseEndpoint(localText);
  if (!local) return null;

  const remote = remoteText ? parseEndpoint(remoteText) : null;

  return { local, remote };
}

function parseEndpoint(value) {
  const text = value.trim();
  if (!text) return null;

  if (text.startsWith("[")) {
    const closing = text.lastIndexOf("]:");
    if (closing < 0) return null;

    const host = text.slice(1, closing);
    const portText = text.slice(closing + 2);
    return endpoint(host, portText);
  }

  const colon = text.lastIndexOf(":");
  if (colon < 0) return null;

  return endpoint(text.slice(0, colon), text.slice(colon + 1));
}

function endpoint(host, portText) {
  const port = Number(portText);
  if (!Number.isInteger(port)) return null;

  return {
    host: normalizeHost(host),
    port
  };
}

function normalizeHost(host) {
  return String(host || "")
    .trim()
    .replace(/^\[/, "")
    .replace(/\]$/, "")
    .replace(/%.+$/, "")
    .toLowerCase();
}

function socketBelongsToInterface(socket, interfaceAddresses, interfaceName) {
  const host = normalizeHost(socket.local?.host);
  if (!host || host === "*") return true;
  if (interfaceAddresses.has(host)) return true;

  const loopback = host === "127.0.0.1" || host === "::1";
  return loopback && interfaceName === "lo0";
}

function summarizeProcess(process, interfaceAddresses, interfaceName) {
  const sockets = process.sockets.filter((socket) =>
    socketBelongsToInterface(socket, interfaceAddresses, interfaceName)
  );

  const established = sockets.filter((socket) => socket.state === "ESTABLISHED").length;
  const listeners = sockets.filter((socket) => socket.state === "LISTEN").length;
  const tcp = sockets.filter((socket) => socket.protocol === "TCP").length;
  const udp = sockets.filter((socket) => socket.protocol === "UDP").length;

  return {
    ...process,
    sockets,
    established,
    listeners,
    tcp,
    udp
  };
}

async function chooseFromNumberedList(title, choices, formatChoice) {
  const rl = createPromiseInterface({ input: stdin, output: stdout });

  try {
    while (true) {
      heading(title);

      choices.forEach((choice, index) => {
        stdout.write(`  ${color(ANSI.cyan, String(index + 1).padStart(2))}. ${formatChoice(choice)}\n`);
      });

      const answer = (await rl.question("\nChoose a number: ")).trim();
      const index = Number(answer) - 1;

      if (Number.isInteger(index) && index >= 0 && index < choices.length) {
        return choices[index];
      }

      stdout.write(color(ANSI.yellow, "Please enter one of the displayed numbers.\n"));
    }
  } finally {
    rl.close();
  }
}

async function chooseProcess(interfaceName, interfaceAddresses) {
  const rl = createPromiseInterface({ input: stdin, output: stdout });

  try {
    let query = "";

    while (true) {
      const allProcesses = await listNetworkProcesses();
      const candidates = allProcesses
        .map((process) => summarizeProcess(process, interfaceAddresses, interfaceName))
        .filter((process) => process.sockets.length > 0)
        .filter((process) => {
          if (!query) return true;
          const haystack = `${process.displayName} ${process.command} ${process.pid}`.toLowerCase();
          return haystack.includes(query.toLowerCase());
        })
        .sort((a, b) => {
          const aGui = a.executable.includes(".app/Contents/MacOS/") ? 1 : 0;
          const bGui = b.executable.includes(".app/Contents/MacOS/") ? 1 : 0;
          if (aGui !== bGui) return bGui - aGui;
          if (a.established !== b.established) return b.established - a.established;
          return a.displayName.localeCompare(b.displayName);
        });

      heading(`Apps using ${interfaceName}`);

      if (candidates.length === 0) {
        stdout.write("  No matching network processes were found.\n");
      } else {
        candidates.forEach((process, index) => {
          const detail = [
            process.established ? `${process.established} connected` : "",
            process.listeners ? `${process.listeners} listening` : "",
            process.tcp ? `${process.tcp} TCP` : "",
            process.udp ? `${process.udp} UDP` : ""
          ]
            .filter(Boolean)
            .join(", ");

          stdout.write(
            `  ${color(ANSI.cyan, String(index + 1).padStart(2))}. ` +
              `${color(ANSI.bold, process.displayName)} ` +
              `${color(ANSI.dim, `[PID ${process.pid}]`)} ` +
              `${color(ANSI.dim, detail)}\n`
          );
        });
      }

      stdout.write(
        `\n${color(ANSI.dim, "Enter a number, type part of an app name to filter, r to rescan, or q to quit.")}\n`
      );

      const answer = (await rl.question("Selection: ")).trim();
      if (!answer) continue;
      if (answer.toLowerCase() === "q") return null;
      if (answer.toLowerCase() === "r") {
        query = "";
        continue;
      }

      const selectedIndex = Number(answer) - 1;
      if (
        Number.isInteger(selectedIndex) &&
        selectedIndex >= 0 &&
        selectedIndex < candidates.length
      ) {
        return candidates[selectedIndex];
      }

      query = answer;
    }
  } finally {
    rl.close();
  }
}

class SocketTracker {
  constructor(pid) {
    this.pid = pid;
    this.entries = new Map();
    this.timer = null;
    this.refreshing = false;
  }

  async start() {
    await this.refresh();
    this.timer = setInterval(() => {
      void this.refresh();
    }, SOCKET_REFRESH_MS);
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async refresh() {
    if (this.refreshing) return;
    this.refreshing = true;

    try {
      const now = Date.now();
      const sockets = await listSocketsForPid(this.pid);

      for (const socket of sockets) {
        this.entries.set(socketKey(socket), {
          socket,
          expiresAt: now + SOCKET_GRACE_MS
        });
      }

      for (const [key, entry] of this.entries) {
        if (entry.expiresAt < now) this.entries.delete(key);
      }
    } finally {
      this.refreshing = false;
    }
  }

  match(packet) {
    for (const { socket } of this.entries.values()) {
      const match = matchPacketToSocket(packet, socket);
      if (match) return { ...match, socket };
    }

    return null;
  }

  get size() {
    return this.entries.size;
  }
}

function socketKey(socket) {
  const remote = socket.remote
    ? `${socket.remote.host}:${socket.remote.port}`
    : "*";
  return `${socket.protocol}|${socket.local.host}:${socket.local.port}|${remote}|${socket.state}`;
}

function matchPacketToSocket(packet, socket) {
  if (!packet.transport) return null;
  if (packet.transport.protocol !== socket.protocol) return null;

  const srcHost = normalizeHost(packet.source.ip);
  const dstHost = normalizeHost(packet.destination.ip);
  const srcPort = packet.source.port;
  const dstPort = packet.destination.port;

  const localHost = normalizeHost(socket.local.host);
  const localPort = socket.local.port;
  const remoteHost = normalizeHost(socket.remote?.host);
  const remotePort = socket.remote?.port;

  const localHostMatchesSource = localHost === "*" || localHost === srcHost;
  const localHostMatchesDestination = localHost === "*" || localHost === dstHost;
  const remoteHostMatchesDestination = !remoteHost || remoteHost === "*" || remoteHost === dstHost;
  const remoteHostMatchesSource = !remoteHost || remoteHost === "*" || remoteHost === srcHost;
  const remotePortMatchesDestination = remotePort == null || remotePort === dstPort;
  const remotePortMatchesSource = remotePort == null || remotePort === srcPort;

  if (
    srcPort === localPort &&
    localHostMatchesSource &&
    remoteHostMatchesDestination &&
    remotePortMatchesDestination
  ) {
    return { direction: "outbound" };
  }

  if (
    dstPort === localPort &&
    localHostMatchesDestination &&
    remoteHostMatchesSource &&
    remotePortMatchesSource
  ) {
    return { direction: "inbound" };
  }

  return null;
}

async function getSupportedTsharkFields() {
  try {
    const { stdout: output } = await runCommand("tshark", ["-G", "fields"]);
    const supported = new Set();

    for (const line of output.split(/\r?\n/)) {
      if (!line.startsWith("F\t")) continue;
      const parts = line.split("\t");
      if (parts[2]) supported.add(parts[2]);
    }

    return supported;
  } catch {
    return null;
  }
}

async function selectCaptureFields() {
  const supported = await getSupportedTsharkFields();
  if (!supported) return FIELD_SPECS;

  return FIELD_SPECS.filter(([, field]) => {
    return field.startsWith("_ws.col.") || supported.has(field);
  });
}

function parseDelimitedLine(line, delimiter = "\t") {
  const values = [];
  let value = "";
  let quoted = false;

  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];

    if (character === '"') {
      if (quoted && line[index + 1] === '"') {
        value += '"';
        index += 1;
      } else {
        quoted = !quoted;
      }
      continue;
    }

    if (character === delimiter && !quoted) {
      values.push(value);
      value = "";
      continue;
    }

    value += character;
  }

  values.push(value);
  return values;
}

function parseNumber(value) {
  if (value == null || value === "") return undefined;
  const number = Number(value);
  return Number.isFinite(number) ? number : undefined;
}

function firstValue(value) {
  if (!value) return "";
  return String(value).split(",")[0];
}

function parsePacketLine(line, activeFields) {
  const columns = parseDelimitedLine(line);
  const raw = {};

  activeFields.forEach(([key], index) => {
    raw[key] = columns[index] || "";
  });

  const sourceIp = firstValue(raw.ipv4Source || raw.ipv6Source);
  const destinationIp = firstValue(raw.ipv4Destination || raw.ipv6Destination);
  const tcpSourcePort = parseNumber(firstValue(raw.tcpSourcePort));
  const tcpDestinationPort = parseNumber(firstValue(raw.tcpDestinationPort));
  const udpSourcePort = parseNumber(firstValue(raw.udpSourcePort));
  const udpDestinationPort = parseNumber(firstValue(raw.udpDestinationPort));

  const transport = tcpSourcePort != null || tcpDestinationPort != null
    ? {
        protocol: "TCP",
        sourcePort: tcpSourcePort,
        destinationPort: tcpDestinationPort,
        stream: parseNumber(firstValue(raw.tcpStream)),
        flags: firstValue(raw.tcpFlags),
        sequence: parseNumber(firstValue(raw.tcpSequence)),
        acknowledgement: parseNumber(firstValue(raw.tcpAcknowledgement))
      }
    : udpSourcePort != null || udpDestinationPort != null
      ? {
          protocol: "UDP",
          sourcePort: udpSourcePort,
          destinationPort: udpDestinationPort,
          stream: parseNumber(firstValue(raw.udpStream)),
          length: parseNumber(firstValue(raw.udpLength))
        }
      : null;

  const protocolStack = String(raw.protocolStack || "")
    .split(":")
    .filter(Boolean);

  const payloadHex = cleanHex(
    firstValue(raw.tcpPayload || raw.udpPayload || raw.dataPayload)
  );
  const payload = payloadHex ? Buffer.from(payloadHex, "hex") : Buffer.alloc(0);
  const asciiStrings = extractAsciiStrings(payload);

  const encryption = classifyEncryption({
    protocolStack,
    columnProtocol: raw.columnProtocol,
    tlsRecordType: raw.tlsRecordType,
    asciiStrings,
    payloadLength: payload.length
  });

  const network = raw.ipv4Source || raw.ipv4Destination
    ? {
        protocol: "IPv4",
        source: sourceIp,
        destination: destinationIp,
        ttl: parseNumber(firstValue(raw.ipv4Ttl)),
        protocolNumber: parseNumber(firstValue(raw.ipv4Protocol))
      }
    : raw.ipv6Source || raw.ipv6Destination
      ? {
          protocol: "IPv6",
          source: sourceIp,
          destination: destinationIp,
          hopLimit: parseNumber(firstValue(raw.ipv6HopLimit)),
          nextHeader: parseNumber(firstValue(raw.ipv6NextHeader))
        }
      : null;

  const link = raw.ethSource || raw.ethDestination
    ? {
        protocol: "Ethernet",
        source: firstValue(raw.ethSource),
        destination: firstValue(raw.ethDestination),
        encapsulation: firstValue(raw.encapsulation)
      }
    : raw.wlanSource || raw.wlanDestination
      ? {
          protocol: "IEEE 802.11",
          source: firstValue(raw.wlanSource),
          destination: firstValue(raw.wlanDestination),
          encapsulation: firstValue(raw.encapsulation)
        }
      : {
          protocol: protocolStack[0] || "Unknown link layer",
          encapsulation: firstValue(raw.encapsulation)
        };

  const applicationProtocol = firstValue(raw.columnProtocol) ||
    [...protocolStack].reverse().find((name) => !["eth", "ip", "ipv6", "tcp", "udp"].includes(name)) ||
    "Unknown";

  return {
    timestamp: raw.timeEpoch
      ? new Date(Number(raw.timeEpoch) * 1000).toISOString()
      : new Date().toISOString(),
    packetNumber: parseNumber(firstValue(raw.number)),
    frameLength: parseNumber(firstValue(raw.frameLength)),
    capturedLength: parseNumber(firstValue(raw.capturedLength)),
    source: {
      ip: sourceIp,
      port: transport?.sourcePort,
      mac: link.source
    },
    destination: {
      ip: destinationIp,
      port: transport?.destinationPort,
      mac: link.destination
    },
    transport,
    protocolStack,
    osi: {
      layer1: {
        name: "Physical",
        protocol: "Capture interface",
        inferred: true,
        details: {
          note: "Radio frequency, signal strength, and modulation are usually not present in a normal macOS packet capture."
        }
      },
      layer2: {
        name: "Data Link",
        protocol: link.protocol,
        details: link
      },
      layer3: network
        ? {
            name: "Network",
            protocol: network.protocol,
            details: network
          }
        : null,
      layer4: transport
        ? {
            name: "Transport",
            protocol: transport.protocol,
            details: transport
          }
        : null,
      layer5: transport
        ? {
            name: "Session",
            protocol: `${transport.protocol} conversation`,
            inferred: true,
            details: { stream: transport.stream }
          }
        : null,
      layer6: encryption.status === "encrypted"
        ? {
            name: "Presentation",
            protocol: encryption.protocol,
            inferred: true,
            details: {
              tlsRecordType: firstValue(raw.tlsRecordType),
              tlsHandshakeType: firstValue(raw.tlsHandshakeType),
              tlsVersion: firstValue(raw.tlsVersion)
            }
          }
        : {
            name: "Presentation",
            protocol: "No recognized encryption layer",
            inferred: true,
            details: {}
          },
      layer7: {
        name: "Application",
        protocol: applicationProtocol,
        details: {
          info: firstValue(raw.columnInfo),
          httpMethod: firstValue(raw.httpMethod),
          httpHost: firstValue(raw.httpHost),
          httpUri: firstValue(raw.httpUri),
          httpContentType: firstValue(raw.httpContentType),
          dnsQuery: firstValue(raw.dnsQuery)
        }
      }
    },
    encryption,
    payload: payload.length
      ? {
          length: payload.length,
          previewHex: payload.subarray(0, 64).toString("hex"),
          previewAscii: asciiPreview(payload.subarray(0, MAX_ASCII_PREVIEW)),
          readableStrings: asciiStrings
        }
      : null
  };
}

function cleanHex(value) {
  return String(value || "").replace(/[^0-9a-f]/gi, "");
}

function extractAsciiStrings(buffer) {
  if (!buffer.length) return [];

  return [...buffer.toString("latin1").matchAll(/[ -~]{6,}/g)]
    .map((match) => match[0].trim())
    .filter(Boolean)
    .slice(0, 8);
}

function asciiPreview(buffer) {
  return Array.from(buffer)
    .map((byte) => (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : "."))
    .join("");
}

function classifyEncryption({
  protocolStack,
  columnProtocol,
  tlsRecordType,
  asciiStrings,
  payloadLength
}) {
  const normalized = protocolStack.map((name) => name.toLowerCase());
  const column = String(columnProtocol || "").toLowerCase();

  if (normalized.some((name) => name === "tls" || name === "ssl") || column.includes("tls")) {
    return {
      status: "encrypted",
      protocol: "TLS",
      reason: tlsRecordType
        ? `TShark identified TLS record type ${firstValue(tlsRecordType)}.`
        : "TShark identified TLS in the protocol stack."
    };
  }

  if (normalized.some((name) => name.includes("quic")) || column.includes("quic")) {
    return {
      status: "encrypted",
      protocol: "QUIC",
      reason: "TShark identified QUIC, whose application payload is encrypted."
    };
  }

  if (asciiStrings.length > 0) {
    return {
      status: "likely-plaintext",
      protocol: "None detected",
      reason: `Readable payload text was found: ${asciiStrings.slice(0, 3).join(" | ")}`
    };
  }

  if (payloadLength > 0) {
    return {
      status: "unknown",
      protocol: "Unknown",
      reason: "Binary-looking data is not proof of encryption; it may be compressed media or another binary format."
    };
  }

  return {
    status: "unknown",
    protocol: "Unknown",
    reason: "This packet contains no captured transport payload."
  };
}

function formatEndpoint(value) {
  if (!value) return "?";
  const host = value.ip || value.mac || "?";
  return value.port != null ? `${host}:${value.port}` : host;
}

function printPacket(packet) {
  const direction = packet.direction === "outbound" ? "OUT" : "IN ";
  const directionColor = packet.direction === "outbound" ? ANSI.magenta : ANSI.cyan;
  const encryptionColor = packet.encryption.status === "encrypted"
    ? ANSI.green
    : packet.encryption.status === "likely-plaintext"
      ? ANSI.red
      : ANSI.yellow;

  const line = [
    color(ANSI.dim, `#${packet.packetNumber ?? "?"}`),
    color(directionColor, direction),
    `${formatEndpoint(packet.source)} → ${formatEndpoint(packet.destination)}`,
    packet.transport?.protocol || "?",
    packet.osi.layer7?.protocol || "?",
    `${packet.frameLength ?? "?"}B`,
    color(encryptionColor, packet.encryption.status.toUpperCase())
  ].join("  ");

  stdout.write(`${line}\n`);

  if (packet.encryption.status === "likely-plaintext" && packet.payload?.readableStrings.length) {
    stdout.write(
      `    ${color(ANSI.red, "Readable payload:")} ` +
        `${packet.payload.readableStrings.slice(0, 3).join(" | ")}\n`
    );
  }
}

function printOsiLegend() {
  stdout.write(
    color(
      ANSI.dim,
      "Terminal: one line per packet. NDJSON log: full Layer 1–7 breakdown, headers, payload preview, and encryption assessment.\n"
    )
  );
}

function safeFilePart(value) {
  return String(value || "capture")
    .replace(/[^a-z0-9._-]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}

async function captureProcessTraffic({ interfaceInfo, processInfo }) {
  const activeFields = await selectCaptureFields();
  const tracker = new SocketTracker(processInfo.pid);
  await tracker.start();

  mkdirSync("captures", { recursive: true });
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const logPath = join(
    "captures",
    `${timestamp}-${safeFilePart(processInfo.displayName)}-${processInfo.pid}.ndjson`
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
    "occurrence=f"
  ];

  for (const [, field] of activeFields) {
    args.push("-e", field);
  }

  const tshark = spawn("tshark", args, {
    stdio: ["ignore", "pipe", "pipe"]
  });

  let matchedPackets = 0;
  let tsharkError = "";

  heading(`Viewing packets for ${processInfo.displayName} [PID ${processInfo.pid}]`);
  stdout.write(`Interface: ${interfaceInfo.name}${interfaceInfo.description ? ` — ${interfaceInfo.description}` : ""}\n`);
  stdout.write(`Log file: ${logPath}\n`);
  stdout.write(`Tracked sockets: ${tracker.size}\n`);
  printOsiLegend();
  stdout.write(color(ANSI.dim, "Press Ctrl+C to stop.\n\n"));

  const lines = createInterface({ input: tshark.stdout, crlfDelay: Infinity });

  lines.on("line", (line) => {
    if (!line.trim()) return;

    try {
      const packet = parsePacketLine(line, activeFields);
      const match = tracker.match(packet);
      if (!match) return;

      packet.process = {
        pid: processInfo.pid,
        name: processInfo.displayName,
        executable: processInfo.executable
      };
      packet.interface = {
        name: interfaceInfo.name,
        description: interfaceInfo.description
      };
      packet.direction = match.direction;
      packet.matchedSocket = match.socket;

      matchedPackets += 1;
      log.write(`${JSON.stringify(packet)}\n`);
      printPacket(packet);
    } catch (error) {
      stderr.write(`Packet parse warning: ${error.message}\n`);
    }
  });

  tshark.stderr.on("data", (chunk) => {
    const message = chunk.toString();
    tsharkError += message;

    if (message.includes("Capturing on") || message.includes("Packets captured")) {
      return;
    }

    if (!message.toLowerCase().includes("running as user")) {
      stderr.write(color(ANSI.dim, `[tshark] ${message}`));
    }
  });

  const stop = () => {
    tracker.stop();
    if (!tshark.killed) tshark.kill("SIGINT");
  };

  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);

  await new Promise((resolve, reject) => {
    tshark.on("error", reject);
    tshark.on("close", (code) => {
      tracker.stop();
      log.end();
      process.removeListener("SIGINT", stop);
      process.removeListener("SIGTERM", stop);

      stdout.write(`\nCaptured ${matchedPackets} packet(s) for ${processInfo.displayName}.\n`);
      stdout.write(`Saved full records to ${logPath}.\n`);

      if (code && code !== 0) {
        const permissionHint = /permission|bpf|capture privileges/i.test(tsharkError)
          ? " TShark could not access the capture device. Install Wireshark's capture permissions or run the command with appropriate privileges."
          : "";
        reject(new Error(`TShark exited with code ${code}.${permissionHint}`));
      } else {
        resolve();
      }
    });
  });
}

async function main() {
  stdout.write(`${color(ANSI.bold + ANSI.cyan, APP_NAME)}\n`);
  stdout.write(color(ANSI.dim, "Select an interface, choose an app, then inspect only that app's packets.\n"));

  await verifyRequirements();

  const interfaces = await listCaptureInterfaces();
  if (!interfaces.length) {
    throw new Error(
      "TShark returned no capture interfaces. This usually means capture permissions are not configured."
    );
  }

  const interfaceInfo = await chooseFromNumberedList(
    "Network interfaces",
    interfaces,
    (item) => `${color(ANSI.bold, item.name)}${item.description ? ` — ${item.description}` : ""}`
  );

  const addresses = await getInterfaceAddresses(interfaceInfo.name);
  const processInfo = await chooseProcess(interfaceInfo.name, addresses);
  if (!processInfo) return;

  await captureProcessTraffic({ interfaceInfo, processInfo });
}

main().catch((error) => {
  stderr.write(`\n${color(ANSI.red, "Error:")} ${error.message}\n`);
  process.exitCode = 1;
});
