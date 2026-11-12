import * as z from "zod/v4";
import { dbUserSchema, userDbNameSchema } from "../../validate/schemas.ts";
import { ADDS, annotate, defineTool, opt, req, secret, type ToolSpec } from "../define.ts";
import { domainName, fileProblem } from "./common.ts";

const databaseName = userDbNameSchema.describe(
  "Database name: letters, digits and - only, starting with a letter or digit, at most 64. No underscore: CloudPanel rejects it.",
);

const dumpFile = (what: string) =>
  z.string().min(2).max(256).describe(
    `Absolute path of the dump file on the SERVER, in the dumps/ subdirectory of one of the profile's file directories (clp_server_info shows the exact directories), ending in .sql or .sql.gz. ${what}`,
  );

export const databaseTools: ToolSpec[] = [
  defineTool({
    name: "clp_db_add",
    kind: "clpctl",
    command: "db:add",
    cls: "write",
    title: "Add a database",
    summary: "Adds a database with its own database user to an existing site (clpctl db:add).",
    generatesPassword: true,
    shape: {
      domainName,
      databaseName,
      databaseUserName: dbUserSchema.describe("Database user name: letters, digits and _, at most 64. It must not exist yet."),
    },
    annotations: ADDS,
    options: {
      domainName: req("domain"),
      databaseName: req("userDbName"),
      databaseUserName: req("dbUser"),
      databaseUserPassword: req("password"),
    },
    protectOptions: { domainName: "domain", databaseName: "database" },
    plan: (a) => ({
      command: "db:add",
      options: [
        opt("domainName", a.domainName),
        opt("databaseName", a.databaseName),
        opt("databaseUserName", a.databaseUserName),
        secret("databaseUserPassword", "db", a.databaseName, a.databaseUserName),
      ],
      flags: [],
      summary: `Add the database ${a.databaseName} with user ${a.databaseUserName} to ${a.domainName}`,
      effects: [
        `creates the database ${a.databaseName} and the database user ${a.databaseUserName}`,
        "generates a password for the database user, saved in a file on your machine and never shown",
      ],
      undo: "clp_db_delete removes the database (the database user stays until the site is deleted)",
      protect: [
        { kind: "domain", value: a.domainName },
        { kind: "database", value: a.databaseName },
      ],
    }),
  }),
  defineTool({
    name: "clp_db_export",
    kind: "clpctl",
    command: "db:export",
    cls: "write",
    title: "Export a database to a file on the server",
    summary:
      "Exports a database to a dump file on the server (clpctl db:export, mysqldump). The file is written as root into the dumps/ subdirectory of a file directory, and an existing file at that path is overwritten. A name ending in .sql.gz is gzipped. System databases and the panel's own database cannot be exported. Large databases can take minutes.",
    timeout: "db",
    shape: {
      databaseName: databaseName.describe("Database to export."),
      file: dumpFile("An existing file at that path is overwritten."),
    },
    annotations: annotate(false, true, false),
    options: { databaseName: req("userDbName"), file: req("dumpPath") },
    protectOptions: { databaseName: "database" },
    check: (a, p) => fileProblem("file", "dump", String(a["file"]), p),
    plan: (a) => ({
      command: "db:export",
      options: [opt("databaseName", a.databaseName), opt("file", a.file)],
      flags: [],
      summary: `Export the database ${a.databaseName} to ${a.file}`,
      effects: [`writes ${a.file} as root and overwrites it if it exists`],
      undo: `delete the file ${a.file} on the server`,
      protect: [{ kind: "database", value: a.databaseName }],
    }),
  }),
  defineTool({
    name: "clp_db_import",
    kind: "clpctl",
    command: "db:import",
    cls: "destructive",
    title: "Import a dump into a database (overwrites)",
    summary:
      "Imports a dump file from the server into a database (clpctl db:import). It writes into the database and can overwrite existing data; CloudPanel warns against doing this with phpMyAdmin. The file must be in the dumps/ subdirectory of the profile's file directories. A human must type the database name to approve.",
    timeout: "db",
    shape: {
      databaseName: databaseName.describe("Database to import into."),
      file: dumpFile("It must already be on the server."),
    },
    annotations: annotate(false, true, true),
    options: { databaseName: req("userDbName"), file: req("dumpPath") },
    protectOptions: { databaseName: "database" },
    check: (a, p) => fileProblem("file", "dump", String(a["file"]), p),
    plan: (a) => ({
      command: "db:import",
      options: [opt("databaseName", a.databaseName), opt("file", a.file)],
      flags: [],
      summary: `IMPORT ${a.file} into the database ${a.databaseName} (overwrites data)`,
      effects: [`runs the dump's SQL against ${a.databaseName}; existing tables and rows can be replaced`],
      undo: "only from a backup or a dump taken before (clp_db_export)",
      confirm: { target: a.databaseName, noun: "database" },
      protect: [{ kind: "database", value: a.databaseName }],
    }),
  }),
  defineTool({
    name: "clp_db_delete",
    kind: "clpctl",
    command: "db:delete",
    cls: "destructive",
    title: "Delete a database",
    summary:
      "Deletes a database (clpctl db:delete). Not undoable: export it first with clp_db_export if it may be needed. This command is not on CloudPanel's CLI documentation page; it exists on CloudPanel 2.5.4 (observed) and the server reports whether yours has it. On the observed version the database user is left behind. clpctl asks a yes/no question that nobody can answer here: the call is reported as done only if clpctl then says the database has been deleted, otherwise as not confirmed.",
    shape: { databaseName },
    annotations: annotate(false, true, true),
    options: { databaseName: req("userDbName") },
    protectOptions: { databaseName: "database" },
    plan: (a) => ({
      command: "db:delete",
      options: [opt("databaseName", a.databaseName)],
      flags: [],
      doneLine: `The database ${a.databaseName} has been deleted`,
      summary: `DELETE the database ${a.databaseName}`,
      effects: [`drops the database ${a.databaseName} and all its data`, "the database user may remain"],
      undo: "none; restore from a dump or a backup",
      confirm: { target: a.databaseName, noun: "database" },
      protect: [{ kind: "database", value: a.databaseName }],
    }),
  }),
  defineTool({
    name: "clp_db_show_master_credentials",
    kind: "clpctl",
    command: "db:show:master-credentials",
    cls: "admin",
    title: "Save the database master credentials to a local file",
    summary:
      "Runs clpctl db:show:master-credentials, which prints the master database host, user, PASSWORD and port. The whole output is written to a mode-0600 file on the machine this server runs on and is NOT returned: the result only names the file. Use it when the person you are helping wants the credentials; never try to read the password.",
    extraNote: "No output is returned by design.",
    shape: {},
    annotations: annotate(false, false, true),
    options: {},
    plan: () => ({
      command: "db:show:master-credentials",
      options: [],
      flags: [],
      summary: "Write the database master credentials to a local secrets file",
      effects: ["prints the master database password on the server; this server saves it in a 0600 file and shows nothing"],
      undo: "delete the file; rotate the master password in CloudPanel if it leaked",
      confirm: { target: "show-master-credentials", noun: "phrase" },
      protect: [],
      captureToFile: true,
    }),
  }),
];
