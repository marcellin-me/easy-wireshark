import assert from "node:assert/strict";
import test from "node:test";
import { classifyEncryption, firstValue, parseDelimitedLine, parseNumber, parsePacketLine } from "./packet.js";
import type { FieldSpec } from "./types.js";

test("parses quoted TShark columns", () => assert.deepEqual(parseDelimitedLine('one\t"two\tthree"\t"four""five"'), ["one", "two\tthree", 'four"five']));
test("normalizes first and numeric values", () => { assert.equal(firstValue("80,443"), "80"); assert.equal(parseNumber("42"), 42); assert.equal(parseNumber("NaN"), undefined); });
test("classifies TLS, QUIC, plaintext, binary, and empty payloads", () => {
  assert.equal(classifyEncryption({ protocolStack: ["eth", "tls"], columnProtocol: "", tlsRecordType: "23", asciiStrings: [], payloadLength: 0 }).status, "encrypted");
  assert.equal(classifyEncryption({ protocolStack: ["quic"], columnProtocol: "", tlsRecordType: "", asciiStrings: [], payloadLength: 0 }).protocol, "QUIC");
  assert.equal(classifyEncryption({ protocolStack: [], columnProtocol: "", tlsRecordType: "", asciiStrings: ["hello world"], payloadLength: 11 }).status, "likely-plaintext");
  assert.equal(classifyEncryption({ protocolStack: [], columnProtocol: "", tlsRecordType: "", asciiStrings: [], payloadLength: 2 }).status, "unknown");
  assert.match(classifyEncryption({ protocolStack: [], columnProtocol: "", tlsRecordType: "", asciiStrings: [], payloadLength: 0 }).reason, /no captured/i);
});
test("constructs a TCP packet from TShark fields", () => {
  const fields: FieldSpec[] = [{ key: "timeEpoch", field: "frame.time_epoch" }, { key: "ipv4Source", field: "ip.src" }, { key: "ipv4Destination", field: "ip.dst" }, { key: "tcpSourcePort", field: "tcp.srcport" }, { key: "tcpDestinationPort", field: "tcp.dstport" }, { key: "protocolStack", field: "frame.protocols" }];
  const packet = parsePacketLine("1700000000\t10.0.0.1\t1.1.1.1\t50000\t443\teth:ip:tcp", fields);
  assert.deepEqual(packet.transport, { protocol: "TCP", sourcePort: 50000, destinationPort: 443, stream: undefined, flags: "", sequence: undefined, acknowledgement: undefined });
  assert.equal(packet.osi.layer3 && (packet.osi.layer3 as { protocol: string }).protocol, "IPv4");
});
