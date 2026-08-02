import { createInterface as createPromiseInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { ANSI } from "./constants.js";
import { listNetworkProcesses, summarizeProcess } from "./discovery.js";
import { color, heading } from "./terminal.js";
import type { NetworkProcess } from "./types.js";

export async function chooseFromNumberedList<T>(
  title: string,
  choices: T[],
  formatChoice: (choice: T) => string,
): Promise<T> {
  const rl = createPromiseInterface({ input: stdin, output: stdout });
  try {
    while (true) {
      heading(title);
      choices.forEach((choice, index) =>
        stdout.write(
          `  ${color(ANSI.cyan, String(index + 1).padStart(2))}. ${formatChoice(choice)}\n`,
        ),
      );
      const index =
        Number((await rl.question("\nChoose a number: ")).trim()) - 1;
      if (Number.isInteger(index) && index >= 0 && index < choices.length)
        return choices[index];
      stdout.write(
        color(ANSI.yellow, "Please enter one of the displayed numbers.\n"),
      );
    }
  } finally {
    rl.close();
  }
}
export async function chooseProcess(
  interfaceName: string,
  addresses: Set<string>,
): Promise<NetworkProcess | null> {
  const rl = createPromiseInterface({ input: stdin, output: stdout });
  try {
    let query = "";
    while (true) {
      const candidates = (await listNetworkProcesses())
        .map((process) => summarizeProcess(process, addresses, interfaceName))
        .filter((process) => process.sockets.length > 0)
        .filter(
          (process) =>
            !query ||
            `${process.displayName} ${process.command} ${process.pid}`
              .toLowerCase()
              .includes(query.toLowerCase()),
        )
        .sort((a, b) => {
          const aGui = a.executable.includes(".app/Contents/MacOS/") ? 1 : 0;
          const bGui = b.executable.includes(".app/Contents/MacOS/") ? 1 : 0;
          return aGui !== bGui
            ? bGui - aGui
            : a.established !== b.established
              ? b.established - a.established
              : a.displayName.localeCompare(b.displayName);
        });
      heading(`Apps using ${interfaceName}`);
      if (!candidates.length)
        stdout.write("  No matching network processes were found.\n");
      else
        candidates.forEach((process, index) => {
          const detail = [
            process.established ? `${process.established} connected` : "",
            process.listeners ? `${process.listeners} listening` : "",
            process.tcp ? `${process.tcp} TCP` : "",
            process.udp ? `${process.udp} UDP` : "",
          ]
            .filter(Boolean)
            .join(", ");
          stdout.write(
            `  ${color(ANSI.cyan, String(index + 1).padStart(2))}. ${color(ANSI.bold, process.displayName)} ${color(ANSI.dim, `[PID ${process.pid}]`)} ${color(ANSI.dim, detail)}\n`,
          );
        });
      stdout.write(
        `\n${color(ANSI.dim, "Enter a number, type part of an app name to filter, r to rescan, or q to quit.")}\n`,
      );
      const answer = (await rl.question("Selection: ")).trim();
      if (!answer) continue;
      if (answer.toLowerCase() === "q") return null;
      if (answer.toLowerCase() === "r") {
        query = "";
        continue;
      }
      const selected = Number(answer) - 1;
      if (
        Number.isInteger(selected) &&
        selected >= 0 &&
        selected < candidates.length
      )
        return candidates[selected];
      query = answer;
    }
  } finally {
    rl.close();
  }
}
