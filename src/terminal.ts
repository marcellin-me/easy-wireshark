import { stdout } from "node:process";
import { ANSI } from "./constants.js";

export function color(code: string, text: string): string { return stdout.isTTY ? `${code}${text}${ANSI.reset}` : text; }
export function heading(text: string): void { stdout.write(`\n${color(ANSI.bold + ANSI.cyan, text)}\n`); }
