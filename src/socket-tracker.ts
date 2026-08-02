import { SOCKET_GRACE_MS, SOCKET_REFRESH_MS } from "./constants.js";
import { listSocketsForPid, normalizeHost } from "./discovery.js";
import type { Direction, Packet, SocketRecord } from "./types.js";

export function socketKey(socket: SocketRecord): string {
  const remote = socket.remote
    ? `${socket.remote.host}:${socket.remote.port}`
    : "*";
  return `${socket.protocol}|${socket.local.host}:${socket.local.port}|${remote}|${socket.state}`;
}
export function matchPacketToSocket(
  packet: Packet,
  socket: SocketRecord,
): { direction: Direction } | null {
  if (!packet.transport || packet.transport.protocol !== socket.protocol)
    return null;
  const sourceHost = normalizeHost(packet.source.ip);
  const destinationHost = normalizeHost(packet.destination.ip);
  const sourcePort = packet.source.port;
  const destinationPort = packet.destination.port;
  const localHost = normalizeHost(socket.local.host);
  const remoteHost = normalizeHost(socket.remote?.host);
  const remotePort = socket.remote?.port;
  const localSource = localHost === "*" || localHost === sourceHost;
  const localDestination = localHost === "*" || localHost === destinationHost;
  const remoteDestination =
    !remoteHost || remoteHost === "*" || remoteHost === destinationHost;
  const remoteSource =
    !remoteHost || remoteHost === "*" || remoteHost === sourceHost;
  const remotePortDestination =
    remotePort == null || remotePort === destinationPort;
  const remotePortSource = remotePort == null || remotePort === sourcePort;
  if (
    sourcePort === socket.local.port &&
    localSource &&
    remoteDestination &&
    remotePortDestination
  )
    return { direction: "outbound" };
  if (
    destinationPort === socket.local.port &&
    localDestination &&
    remoteSource &&
    remotePortSource
  )
    return { direction: "inbound" };
  return null;
}
export class SocketTracker {
  private readonly entries = new Map<
    string,
    { socket: SocketRecord; expiresAt: number }
  >();
  private timer: NodeJS.Timeout | null = null;
  private refreshing = false;
  constructor(private readonly pid: number) {}
  async start(): Promise<void> {
    await this.refresh();
    this.timer = setInterval(() => {
      void this.refresh();
    }, SOCKET_REFRESH_MS);
  }
  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }
  async refresh(): Promise<void> {
    if (this.refreshing) return;
    this.refreshing = true;
    try {
      const now = Date.now();
      for (const socket of await listSocketsForPid(this.pid))
        this.entries.set(socketKey(socket), {
          socket,
          expiresAt: now + SOCKET_GRACE_MS,
        });
      for (const [key, entry] of this.entries)
        if (entry.expiresAt < now) this.entries.delete(key);
    } finally {
      this.refreshing = false;
    }
  }
  match(packet: Packet): { direction: Direction; socket: SocketRecord } | null {
    for (const { socket } of this.entries.values()) {
      const match = matchPacketToSocket(packet, socket);
      if (match) return { ...match, socket };
    }
    return null;
  }
  get size(): number {
    return this.entries.size;
  }
}
