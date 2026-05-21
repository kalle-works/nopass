import { Command } from "commander";
import { loginCommand } from "./commands/login.js";
import { lockCommand } from "./commands/lock.js";
import { listCommand } from "./commands/list.js";
import { getCommand } from "./commands/get.js";

const program = new Command();

program
  .name("nopwd")
  .description("nopwd CLI — fetch vault secrets for AI agents and scripts")
  .version("0.1.0");

program.addCommand(loginCommand);
program.addCommand(getCommand);
program.addCommand(listCommand);
program.addCommand(lockCommand);

await program.parseAsync(process.argv);
