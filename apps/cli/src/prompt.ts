import { createInterface, type Interface } from "readline";

let sharedRl: Interface | null = null;
// Non-TTY stdin can EOF while the program is mid-derivation between prompts —
// buffer lines as they arrive so later prompts still get their input.
const lineQueue: string[] = [];
const waiting: Array<(line: string) => void> = [];
let stdinEnded = false;

function rl(): Interface {
  if (!sharedRl) {
    sharedRl = createInterface({ input: process.stdin, output: process.stdout });
    sharedRl.on("line", (line) => {
      const next = waiting.shift();
      if (next) next(line.trim());
      else lineQueue.push(line.trim());
    });
    sharedRl.on("close", () => {
      stdinEnded = true;
      // Anything still waiting gets an empty line rather than hanging forever
      while (waiting.length > 0) waiting.shift()!("");
    });
  }
  return sharedRl;
}

export function closePrompt(): void {
  sharedRl?.close();
  sharedRl = null;
}

function nextLine(question: string): Promise<string> {
  process.stdout.write(question);
  const buffered = lineQueue.shift();
  if (buffered !== undefined) {
    process.stdout.write("\n");
    return Promise.resolve(buffered);
  }
  if (stdinEnded) return Promise.resolve("");
  rl();
  return new Promise((resolve) => waiting.push(resolve));
}

/** Interactive prompt; `hidden` suppresses echo for secrets on a TTY.
 *  Piped stdin (tests, scripts) falls back to buffered line reads. */
export function prompt(question: string, hidden = false): Promise<string> {
  if (hidden && process.stdin.isTTY) {
    return new Promise((resolve) => {
      process.stdout.write(question);
      process.stdin.setRawMode?.(true);
      process.stdin.resume();
      let input = "";
      const handler = (chunk: Buffer) => {
        for (const byte of chunk) {
          if (byte === 0x0d || byte === 0x0a) { // enter
            process.stdin.setRawMode?.(false);
            process.stdin.removeListener("data", handler);
            process.stdin.pause();
            process.stdout.write("\n");
            resolve(input);
            return;
          }
          if (byte === 0x03) process.exit(1); // Ctrl+C
          if (byte === 0x7f || byte === 0x08) { input = input.slice(0, -1); continue; } // backspace
          input += String.fromCharCode(byte);
        }
      };
      process.stdin.on("data", handler);
    });
  }

  return nextLine(question);
}
