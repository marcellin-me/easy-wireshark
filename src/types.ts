export type Protocol = "TCP" | "UDP";
export type Direction = "inbound" | "outbound";
export type EncryptionStatus = "encrypted" | "likely-plaintext" | "unknown";

export interface CommandResult {
  stdout: string;
  stderr: string;
}
export interface CommandError extends Error {
  exitCode?: number | null;
  stdout?: string;
  stderr?: string;
}
export interface CaptureInterface {
  number: number;
  name: string;
  description: string;
}
export interface Endpoint {
  host: string;
  port: number;
}
export interface SocketRecord {
  fileDescriptor?: string;
  state: string;
  protocol: Protocol;
  name?: string;
  local: Endpoint;
  remote: Endpoint | null;
}
export interface NetworkProcess {
  pid: number;
  command: string;
  sockets: SocketRecord[];
  executable: string;
  displayName: string;
}
export interface ProcessSummary extends NetworkProcess {
  established: number;
  listeners: number;
  tcp: number;
  udp: number;
}
export interface FieldSpec {
  key: string;
  field: string;
}
export interface Transport {
  protocol: Protocol;
  sourcePort?: number;
  destinationPort?: number;
  stream?: number;
  flags?: string;
  sequence?: number;
  acknowledgement?: number;
  length?: number;
}
export interface PacketEndpoint {
  ip: string;
  port?: number;
  mac?: string;
}
export interface Encryption {
  status: EncryptionStatus;
  protocol: string;
  reason: string;
}
export interface Packet {
  timestamp: string;
  packetNumber?: number;
  frameLength?: number;
  capturedLength?: number;
  source: PacketEndpoint;
  destination: PacketEndpoint;
  transport: Transport | null;
  protocolStack: string[];
  osi: Record<string, unknown>;
  encryption: Encryption;
  payload: {
    length: number;
    previewHex: string;
    previewAscii: string;
    readableStrings: string[];
  } | null;
  process?: { pid: number; name: string; executable: string };
  interface?: { name: string; description: string };
  direction?: Direction;
  matchedSocket?: SocketRecord;
}
