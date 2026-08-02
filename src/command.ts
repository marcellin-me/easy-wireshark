import { spawn } from "node:child_process";
import type { CommandError, CommandResult } from "./types.js";

export function runCommand(
  command: string,
  args: string[],
  options: Parameters<typeof spawn>[2] = {},
): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"],
      ...options,
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve({ stdout, stderr });
      else {
        const error: CommandError = new Error(
          `${command} exited with code ${code}${stderr ? `: ${stderr.trim()}` : ""}`,
        );
        error.exitCode = code;
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
      }
    });
  });
}
export async function commandExists(command: string): Promise<boolean> {
  try {
    await runCommand("/usr/bin/which", [command]);
    return true;
  } catch {
    return false;
  }
}
export async function verifyRequirements(): Promise<void> {
  const missing = (
    await Promise.all(
      ["tshark", "lsof", "ifconfig"].map(async (name) =>
        (await commandExists(name)) ? "" : name,
      ),
    )
  ).filter(Boolean);
  if (missing.length)
    throw new Error(
      `Missing required command(s): ${missing.join(", ")}. Install Wireshark/TShark and make sure the commands are on PATH.`,
    );
}
