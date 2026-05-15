import { Command } from "commander";
import { clearSession } from "../session.js";

export const lockCommand = new Command("lock")
  .description("clear the local session (vault stays encrypted on server)")
  .action(() => {
    clearSession();
    process.stdout.write("Vault locked — session cleared.\n");
  });
