import assert from "node:assert/strict";
import test from "node:test";
import { parseEndpoint, parseLsofFieldOutput, parseSocketName, socketBelongsToInterface } from "./discovery.js";

test("parses lsof records and TCP endpoints", () => {
  const processes = parseLsofFieldOutput("p42\ncSafari\nf12\nPTCP\nn127.0.0.1:51342->1.1.1.1:443\nTST=ESTABLISHED\n");
  assert.equal(processes.length, 1);
  assert.deepEqual(processes[0].sockets[0], { fileDescriptor: "12", state: "ESTABLISHED", protocol: "TCP", local: { host: "127.0.0.1", port: 51342 }, remote: { host: "1.1.1.1", port: 443 } });
});
test("parses IPv6 socket endpoints", () => {
  assert.deepEqual(parseEndpoint("[fe80::1%en0]:5353"), { host: "fe80::1", port: 5353 });
  assert.deepEqual(parseSocketName("[::1]:8000->[::1]:50000"), { local: { host: "::1", port: 8000 }, remote: { host: "::1", port: 50000 } });
});
test("filters wildcard and loopback sockets by interface", () => {
  const socket = { state: "LISTEN", protocol: "TCP" as const, local: { host: "*", port: 80 }, remote: null };
  assert.equal(socketBelongsToInterface(socket, new Set(), "en0"), true);
  assert.equal(socketBelongsToInterface({ ...socket, local: { host: "127.0.0.1", port: 80 } }, new Set(), "en0"), false);
  assert.equal(socketBelongsToInterface({ ...socket, local: { host: "127.0.0.1", port: 80 } }, new Set(), "lo0"), true);
});
