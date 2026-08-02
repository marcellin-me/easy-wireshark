#!/usr/bin/env node
import process, { stderr, stdout } from "node:process";
import { APP_NAME, ANSI } from "./constants.js";
import { captureProcessTraffic } from "./capture.js";
import { getInterfaceAddresses, listCaptureInterfaces } from "./discovery.js";
import { color } from "./terminal.js";
import { chooseFromNumberedList, chooseProcess } from "./ui.js";
import { verifyRequirements } from "./command.js";

async function main(): Promise<void> {
  stdout.write(
    `${color(ANSI.bold + ANSI.cyan, APP_NAME)}\n${color(ANSI.dim, "Select an interface, choose an app, then inspect only that app's packets.\n")}`,
  );
  await verifyRequirements();
  const interfaces = await listCaptureInterfaces();
  if (!interfaces.length)
    throw new Error(
      "TShark returned no capture interfaces. This usually means capture permissions are not configured.",
    );
  const interfaceInfo = await chooseFromNumberedList(
    "Network interfaces",
    interfaces,
    (item) =>
      `${color(ANSI.bold, item.name)}${item.description ? ` — ${item.description}` : ""}`,
  );
  const processInfo = await chooseProcess(
    interfaceInfo.name,
    await getInterfaceAddresses(interfaceInfo.name),
  );
  if (processInfo) await captureProcessTraffic({ interfaceInfo, processInfo });
}
main().catch((error: unknown) => {
  stderr.write(
    `\n${color(ANSI.red, "Error:")} ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 1;
});
