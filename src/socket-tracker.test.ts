import assert from "node:assert/strict";
import test from "node:test";
import { matchPacketToSocket, socketKey } from "./socket-tracker.js";
import type { Packet, SocketRecord } from "./types.js";

const socket: SocketRecord = { state: "ESTABLISHED", protocol: "TCP", local: { host: "10.0.0.1", port: 50000 }, remote: { host: "1.1.1.1", port: 443 } };
function packet(source: string, sourcePort: number, destination: string, destinationPort: number): Packet { return { timestamp: "", source: { ip: source, port: sourcePort }, destination: { ip: destination, port: destinationPort }, transport: { protocol: "TCP", sourcePort, destinationPort }, protocolStack: [], osi: {}, encryption: { status: "unknown", protocol: "Unknown", reason: "" }, payload: null }; }
test("matches outbound and inbound packets for an established socket", () => { assert.deepEqual(matchPacketToSocket(packet("10.0.0.1", 50000, "1.1.1.1", 443), socket), { direction: "outbound" }); assert.deepEqual(matchPacketToSocket(packet("1.1.1.1", 443, "10.0.0.1", 50000), socket), { direction: "inbound" }); });
test("matches wildcard listeners but rejects another remote endpoint", () => { const listener: SocketRecord = { ...socket, state: "LISTEN", local: { host: "*", port: 8080 }, remote: null }; assert.deepEqual(matchPacketToSocket(packet("2.2.2.2", 40000, "10.0.0.1", 8080), listener), { direction: "inbound" }); assert.equal(matchPacketToSocket(packet("10.0.0.1", 50000, "2.2.2.2", 443), socket), null); });
test("creates stable socket keys", () => assert.equal(socketKey(socket), "TCP|10.0.0.1:50000|1.1.1.1:443|ESTABLISHED"));
