import { Buffer } from "node:buffer";
import { MAX_ASCII_PREVIEW, FIELD_SPECS } from "./constants.js";
import { runCommand } from "./command.js";
import type { Encryption, FieldSpec, Packet, Transport } from "./types.js";

export async function selectCaptureFields(): Promise<FieldSpec[]> {
  try {
    const { stdout } = await runCommand("tshark", ["-G", "fields"]);
    const supported = new Set(
      stdout
        .split(/\r?\n/)
        .filter((line) => line.startsWith("F\t"))
        .map((line) => line.split("\t")[2])
        .filter((field): field is string => Boolean(field)),
    );
    return FIELD_SPECS.filter(
      ({ field }) => field.startsWith("_ws.col.") || supported.has(field),
    );
  } catch {
    return FIELD_SPECS;
  }
}
export function parseDelimitedLine(line: string, delimiter = "\t"): string[] {
  const values: string[] = [];
  let value = "";
  let quoted = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (character === '"') {
      if (quoted && line[index + 1] === '"') {
        value += '"';
        index += 1;
      } else quoted = !quoted;
    } else if (character === delimiter && !quoted) {
      values.push(value);
      value = "";
    } else value += character;
  }
  values.push(value);
  return values;
}
export function parseNumber(value: string | undefined): number | undefined {
  if (value == null || value === "") return undefined;
  const number = Number(value);
  return Number.isFinite(number) ? number : undefined;
}
export function firstValue(value: string | undefined): string {
  return value ? String(value).split(",")[0] : "";
}
export function cleanHex(value: string | undefined): string {
  return String(value || "").replace(/[^0-9a-f]/gi, "");
}
export function extractAsciiStrings(buffer: Buffer): string[] {
  return buffer.length
    ? [...buffer.toString("latin1").matchAll(/[ -~]{6,}/g)]
        .map((match) => match[0].trim())
        .filter(Boolean)
        .slice(0, 8)
    : [];
}
export function asciiPreview(buffer: Buffer): string {
  return Array.from(buffer)
    .map((byte) =>
      byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".",
    )
    .join("");
}
export function classifyEncryption({
  protocolStack,
  columnProtocol,
  tlsRecordType,
  asciiStrings,
  payloadLength,
}: {
  protocolStack: string[];
  columnProtocol?: string;
  tlsRecordType?: string;
  asciiStrings: string[];
  payloadLength: number;
}): Encryption {
  const normalized = protocolStack.map((name) => name.toLowerCase());
  const column = String(columnProtocol || "").toLowerCase();
  if (
    normalized.some((name) => name === "tls" || name === "ssl") ||
    column.includes("tls")
  )
    return {
      status: "encrypted",
      protocol: "TLS",
      reason: tlsRecordType
        ? `TShark identified TLS record type ${firstValue(tlsRecordType)}.`
        : "TShark identified TLS in the protocol stack.",
    };
  if (
    normalized.some((name) => name.includes("quic")) ||
    column.includes("quic")
  )
    return {
      status: "encrypted",
      protocol: "QUIC",
      reason: "TShark identified QUIC, whose application payload is encrypted.",
    };
  if (asciiStrings.length)
    return {
      status: "likely-plaintext",
      protocol: "None detected",
      reason: `Readable payload text was found: ${asciiStrings.slice(0, 3).join(" | ")}`,
    };
  return payloadLength
    ? {
        status: "unknown",
        protocol: "Unknown",
        reason:
          "Binary-looking data is not proof of encryption; it may be compressed media or another binary format.",
      }
    : {
        status: "unknown",
        protocol: "Unknown",
        reason: "This packet contains no captured transport payload.",
      };
}
export function parsePacketLine(
  line: string,
  activeFields: FieldSpec[],
): Packet {
  const columns = parseDelimitedLine(line);
  const raw: Record<string, string> = {};
  activeFields.forEach(({ key }, index) => {
    raw[key] = columns[index] || "";
  });
  const sourceIp = firstValue(raw.ipv4Source || raw.ipv6Source);
  const destinationIp = firstValue(raw.ipv4Destination || raw.ipv6Destination);
  const tcpSourcePort = parseNumber(firstValue(raw.tcpSourcePort));
  const tcpDestinationPort = parseNumber(firstValue(raw.tcpDestinationPort));
  const udpSourcePort = parseNumber(firstValue(raw.udpSourcePort));
  const udpDestinationPort = parseNumber(firstValue(raw.udpDestinationPort));
  const transport: Transport | null =
    tcpSourcePort != null || tcpDestinationPort != null
      ? {
          protocol: "TCP",
          sourcePort: tcpSourcePort,
          destinationPort: tcpDestinationPort,
          stream: parseNumber(firstValue(raw.tcpStream)),
          flags: firstValue(raw.tcpFlags),
          sequence: parseNumber(firstValue(raw.tcpSequence)),
          acknowledgement: parseNumber(firstValue(raw.tcpAcknowledgement)),
        }
      : udpSourcePort != null || udpDestinationPort != null
        ? {
            protocol: "UDP",
            sourcePort: udpSourcePort,
            destinationPort: udpDestinationPort,
            stream: parseNumber(firstValue(raw.udpStream)),
            length: parseNumber(firstValue(raw.udpLength)),
          }
        : null;
  const protocolStack = String(raw.protocolStack || "")
    .split(":")
    .filter(Boolean);
  const payload = Buffer.from(
    cleanHex(firstValue(raw.tcpPayload || raw.udpPayload || raw.dataPayload)),
    "hex",
  );
  const asciiStrings = extractAsciiStrings(payload);
  const encryption = classifyEncryption({
    protocolStack,
    columnProtocol: raw.columnProtocol,
    tlsRecordType: raw.tlsRecordType,
    asciiStrings,
    payloadLength: payload.length,
  });
  const network =
    raw.ipv4Source || raw.ipv4Destination
      ? {
          protocol: "IPv4",
          source: sourceIp,
          destination: destinationIp,
          ttl: parseNumber(firstValue(raw.ipv4Ttl)),
          protocolNumber: parseNumber(firstValue(raw.ipv4Protocol)),
        }
      : raw.ipv6Source || raw.ipv6Destination
        ? {
            protocol: "IPv6",
            source: sourceIp,
            destination: destinationIp,
            hopLimit: parseNumber(firstValue(raw.ipv6HopLimit)),
            nextHeader: parseNumber(firstValue(raw.ipv6NextHeader)),
          }
        : null;
  const link =
    raw.ethSource || raw.ethDestination
      ? {
          protocol: "Ethernet",
          source: firstValue(raw.ethSource),
          destination: firstValue(raw.ethDestination),
          encapsulation: firstValue(raw.encapsulation),
        }
      : raw.wlanSource || raw.wlanDestination
        ? {
            protocol: "IEEE 802.11",
            source: firstValue(raw.wlanSource),
            destination: firstValue(raw.wlanDestination),
            encapsulation: firstValue(raw.encapsulation),
          }
        : {
            protocol: protocolStack[0] || "Unknown link layer",
            encapsulation: firstValue(raw.encapsulation),
          };
  const applicationProtocol =
    firstValue(raw.columnProtocol) ||
    [...protocolStack]
      .reverse()
      .find((name) => !["eth", "ip", "ipv6", "tcp", "udp"].includes(name)) ||
    "Unknown";
  return {
    timestamp: raw.timeEpoch
      ? new Date(Number(raw.timeEpoch) * 1000).toISOString()
      : new Date().toISOString(),
    packetNumber: parseNumber(firstValue(raw.number)),
    frameLength: parseNumber(firstValue(raw.frameLength)),
    capturedLength: parseNumber(firstValue(raw.capturedLength)),
    source: { ip: sourceIp, port: transport?.sourcePort, mac: link.source },
    destination: {
      ip: destinationIp,
      port: transport?.destinationPort,
      mac: link.destination,
    },
    transport,
    protocolStack,
    osi: {
      layer1: {
        name: "Physical",
        protocol: "Capture interface",
        inferred: true,
        details: {
          note: "Radio frequency, signal strength, and modulation are usually not present in a normal macOS packet capture.",
        },
      },
      layer2: { name: "Data Link", protocol: link.protocol, details: link },
      layer3: network
        ? { name: "Network", protocol: network.protocol, details: network }
        : null,
      layer4: transport
        ? {
            name: "Transport",
            protocol: transport.protocol,
            details: transport,
          }
        : null,
      layer5: transport
        ? {
            name: "Session",
            protocol: `${transport.protocol} conversation`,
            inferred: true,
            details: { stream: transport.stream },
          }
        : null,
      layer6:
        encryption.status === "encrypted"
          ? {
              name: "Presentation",
              protocol: encryption.protocol,
              inferred: true,
              details: {
                tlsRecordType: firstValue(raw.tlsRecordType),
                tlsHandshakeType: firstValue(raw.tlsHandshakeType),
                tlsVersion: firstValue(raw.tlsVersion),
              },
            }
          : {
              name: "Presentation",
              protocol: "No recognized encryption layer",
              inferred: true,
              details: {},
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
          dnsQuery: firstValue(raw.dnsQuery),
        },
      },
    },
    encryption,
    payload: payload.length
      ? {
          length: payload.length,
          previewHex: payload.subarray(0, 64).toString("hex"),
          previewAscii: asciiPreview(payload.subarray(0, MAX_ASCII_PREVIEW)),
          readableStrings: asciiStrings,
        }
      : null,
  };
}
