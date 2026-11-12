/** Command-line wrapper of the clpctl simulator: state lives in the JSON file named by CLPCTL_SIM_STATE. */
import { appendFileSync } from "node:fs";
import { ClpctlSim, loadState, saveState } from "./clpctl.ts";

const statePath = process.env["CLPCTL_SIM_STATE"];
if (statePath === undefined || statePath === "") {
  process.stderr.write("CLPCTL_SIM_STATE is not set\n");
  process.exit(99);
}
const argv = process.argv.slice(2);
const log = process.env["CLPCTL_SIM_LOG"];
if (log !== undefined && log !== "") {
  appendFileSync(log, `${JSON.stringify({ argv, as: process.env["CLPCTL_SIM_AS"] ?? "root" })}\n`);
}
const state = loadState(statePath);
const sim = new ClpctlSim(state, {
  errorExitCode: Number(process.env["CLPCTL_SIM_ERROR_EXIT"] ?? "1"),
  runAs: process.env["CLPCTL_SIM_AS"] ?? "root",
});
const result = sim.run(argv);
saveState(statePath, state);
process.stdout.write(result.stdout);
process.stderr.write(result.stderr);
process.exitCode = result.exitCode;
