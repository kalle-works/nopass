/** Render and download the plain-text recovery kit file. */

export function buildRecoveryKitText(email: string, code: string): string {
  return [
    "nopwd recovery kit",
    "==================",
    "",
    `Account:        ${email}`,
    `Recovery code:  ${code}`,
    "",
    "This code is the ONLY way back into your vault if you forget your",
    "master password. Anyone holding it (together with your email) can",
    "take over the account, so treat it like cash:",
    "",
    "  - print it and keep it somewhere safe, or",
    "  - store it in a safe-deposit box or fireproof safe",
    "",
    "Do NOT keep it on this computer or in your email.",
    "",
    "To recover: https://nopwd.dev/recover",
    `Generated:   ${new Date().toISOString()}`,
    "",
  ].join("\n");
}

export function downloadRecoveryKit(email: string, code: string): void {
  const blob = new Blob([buildRecoveryKitText(email, code)], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "nopwd-recovery-kit.txt";
  a.click();
  URL.revokeObjectURL(url);
}
