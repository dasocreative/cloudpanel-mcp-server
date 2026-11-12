import * as z from "zod/v4";
import { proxyUrlProblem } from "../../validate/patterns.ts";
import {
  appPortSchema,
  nodejsVersionSchema,
  phpVersionSchema,
  pythonVersionSchema,
} from "../../validate/schemas.ts";
import type { ProtectCheck } from "../../policy/protect.ts";
import { ADDS, annotate, defineTool, opt, req, secret, type ToolSpec } from "../define.ts";
import { domainName, portProblem, siteUser, templateName } from "./common.ts";

const PASSWORD_EFFECT = "generates a password for the site user, saved in a file on your machine and never shown";

function userEffects(user: string): string[] {
  return [`creates the system user ${user} with home /home/${user}`, PASSWORD_EFFECT];
}

const UNDO_ADD = "clp_site_delete removes the site and everything in it";

/** A new site may not take a protected domain (or a name below a protected wildcard) or a protected site user name. */
const NEW_SITE_PROTECT = { domainName: "domain", siteUser: "siteUser" } as const;
const protectNew = (domain: string, user: string): ProtectCheck[] => [
  { kind: "domain", value: domain },
  { kind: "siteUser", value: user },
];

export const siteTools: ToolSpec[] = [
  defineTool({
    name: "clp_site_add_php",
    kind: "clpctl",
    command: "site:add:php",
    cls: "write",
    title: "Add a PHP site",
    summary:
      "Creates a PHP site (clpctl site:add:php): site user, NGINX vhost from a vhost template, PHP-FPM. The template must be one that clp_vhost_templates_list shows (applications such as Laravel, Symfony, WordPress-style apps are templates). With www in the domain, the other form redirects to it and HTTP redirects to HTTPS.",
    generatesPassword: true,
    shape: {
      domainName,
      phpVersion: phpVersionSchema.describe('PHP version as "8.4"; it must be installed (CloudPanel 2.5.x ships 7.1-8.5).'),
      vhostTemplate: templateName,
      siteUser,
    },
    annotations: ADDS,
    options: {
      domainName: req("domain"),
      phpVersion: req("phpVersion"),
      vhostTemplate: req("templateName"),
      siteUser: req("siteUser"),
      siteUserPassword: req("password"),
    },
    protectOptions: NEW_SITE_PROTECT,
    plan: (a) => ({
      command: "site:add:php",
      options: [
        opt("domainName", a.domainName),
        opt("phpVersion", a.phpVersion),
        opt("vhostTemplate", a.vhostTemplate),
        opt("siteUser", a.siteUser),
        secret("siteUserPassword", "site", a.domainName, a.siteUser),
      ],
      flags: [],
      summary: `Add a PHP ${a.phpVersion} site ${a.domainName} (vhost template "${a.vhostTemplate}", site user ${a.siteUser})`,
      effects: [...userEffects(a.siteUser), `creates the NGINX vhost and a PHP-FPM pool for ${a.domainName}`],
      undo: UNDO_ADD,
      protect: protectNew(a.domainName, a.siteUser),
    }),
  }),
  defineTool({
    name: "clp_site_add_nodejs",
    kind: "clpctl",
    command: "site:add:nodejs",
    cls: "write",
    title: "Add a Node.js site",
    summary:
      "Creates a Node.js site (clpctl site:add:nodejs): site user, NGINX vhost that proxies to the app port, Node via nvm. The app itself is uploaded by the site user afterwards.",
    generatesPassword: true,
    shape: {
      domainName,
      nodejsVersion: nodejsVersionSchema.describe('Node.js major version such as "22"; it must be offered by this CloudPanel (12-24 in 2.5.x).'),
      appPort: appPortSchema.describe("TCP port the Node.js app listens on. Only the ports the profile allows (clp_server_info shows appPorts; by default 1337, 2368, 3000-4999, 5000, 5173 and 8000-8199)."),
      siteUser,
    },
    annotations: ADDS,
    options: {
      domainName: req("domain"),
      nodejsVersion: req("nodejsVersion"),
      appPort: req("port"),
      siteUser: req("siteUser"),
      siteUserPassword: req("password"),
    },
    protectOptions: NEW_SITE_PROTECT,
    check: (a, p) => portProblem("appPort", Number(a["appPort"]), p),
    plan: (a) => ({
      command: "site:add:nodejs",
      options: [
        opt("domainName", a.domainName),
        opt("nodejsVersion", a.nodejsVersion),
        opt("appPort", String(a.appPort)),
        opt("siteUser", a.siteUser),
        secret("siteUserPassword", "site", a.domainName, a.siteUser),
      ],
      flags: [],
      summary: `Add a Node.js ${a.nodejsVersion} site ${a.domainName} (app port ${a.appPort}, site user ${a.siteUser})`,
      effects: [...userEffects(a.siteUser), `creates an NGINX vhost for ${a.domainName} that proxies to 127.0.0.1:${a.appPort}`],
      undo: UNDO_ADD,
      protect: protectNew(a.domainName, a.siteUser),
    }),
  }),
  defineTool({
    name: "clp_site_add_python",
    kind: "clpctl",
    command: "site:add:python",
    cls: "write",
    title: "Add a Python site",
    summary:
      "Creates a Python site (clpctl site:add:python): site user, NGINX vhost that proxies to the app port. The Python version must already be installed on the server (the OS default, or one added by the operator).",
    generatesPassword: true,
    shape: {
      domainName,
      pythonVersion: pythonVersionSchema.describe('Python version such as "3.12"; Ubuntu 22.04 ships 3.10, 24.04 3.12.'),
      appPort: appPortSchema.describe("TCP port the Python app listens on. Only the ports the profile allows (clp_server_info shows appPorts; by default 1337, 2368, 3000-4999, 5000, 5173 and 8000-8199)."),
      siteUser,
    },
    annotations: ADDS,
    options: {
      domainName: req("domain"),
      pythonVersion: req("pythonVersion"),
      appPort: req("port"),
      siteUser: req("siteUser"),
      siteUserPassword: req("password"),
    },
    protectOptions: NEW_SITE_PROTECT,
    check: (a, p) => portProblem("appPort", Number(a["appPort"]), p),
    plan: (a) => ({
      command: "site:add:python",
      options: [
        opt("domainName", a.domainName),
        opt("pythonVersion", a.pythonVersion),
        opt("appPort", String(a.appPort)),
        opt("siteUser", a.siteUser),
        secret("siteUserPassword", "site", a.domainName, a.siteUser),
      ],
      flags: [],
      summary: `Add a Python ${a.pythonVersion} site ${a.domainName} (app port ${a.appPort}, site user ${a.siteUser})`,
      effects: [...userEffects(a.siteUser), `creates an NGINX vhost for ${a.domainName} that proxies to 127.0.0.1:${a.appPort}`],
      undo: UNDO_ADD,
      protect: protectNew(a.domainName, a.siteUser),
    }),
  }),
  defineTool({
    name: "clp_site_add_static",
    kind: "clpctl",
    command: "site:add:static",
    cls: "write",
    title: "Add a static HTML site",
    summary: "Creates a static HTML site (clpctl site:add:static): site user and NGINX vhost; the files are uploaded by the site user afterwards.",
    generatesPassword: true,
    shape: { domainName, siteUser },
    annotations: ADDS,
    options: {
      domainName: req("domain"),
      siteUser: req("siteUser"),
      siteUserPassword: req("password"),
    },
    protectOptions: NEW_SITE_PROTECT,
    plan: (a) => ({
      command: "site:add:static",
      options: [
        opt("domainName", a.domainName),
        opt("siteUser", a.siteUser),
        secret("siteUserPassword", "site", a.domainName, a.siteUser),
      ],
      flags: [],
      summary: `Add a static site ${a.domainName} (site user ${a.siteUser})`,
      effects: [...userEffects(a.siteUser), `creates an NGINX vhost for ${a.domainName}`],
      undo: UNDO_ADD,
      protect: protectNew(a.domainName, a.siteUser),
    }),
  }),
  defineTool({
    name: "clp_site_add_reverse_proxy",
    kind: "clpctl",
    command: "site:add:reverse-proxy",
    cls: "write",
    title: "Add a reverse-proxy site",
    summary:
      "Creates a reverse-proxy site (clpctl site:add:reverse-proxy): an NGINX vhost that forwards to an upstream URL. The upstream host must be one the operator allowed for this profile (loopback by default); publishing other services under a domain is refused.",
    generatesPassword: true,
    shape: {
      domainName,
      reverseProxyUrl: z
        .string()
        .min(8)
        .max(300)
        .describe("Upstream URL, http(s)://host[:port][/path], for example http://127.0.0.1:8000. The host must be allowed by the profile (proxyHosts) and the port must be 80, 443 or one the profile allows (appPorts, clp_server_info shows both)."),
      siteUser,
    },
    annotations: ADDS,
    options: {
      domainName: req("domain"),
      reverseProxyUrl: req("proxyUrl"),
      siteUser: req("siteUser"),
      siteUserPassword: req("password"),
    },
    protectOptions: NEW_SITE_PROTECT,
    check: (a, p) => {
      const problem = proxyUrlProblem(String(a["reverseProxyUrl"]), p.proxyHosts, p.appPorts);
      return problem === null ? null : `reverseProxyUrl ${problem}`;
    },
    plan: (a) => ({
      command: "site:add:reverse-proxy",
      options: [
        opt("domainName", a.domainName),
        opt("reverseProxyUrl", a.reverseProxyUrl),
        opt("siteUser", a.siteUser),
        secret("siteUserPassword", "site", a.domainName, a.siteUser),
      ],
      flags: [],
      summary: `Add a reverse-proxy site ${a.domainName} forwarding to ${a.reverseProxyUrl} (site user ${a.siteUser})`,
      effects: [...userEffects(a.siteUser), `makes ${a.reverseProxyUrl} reachable publicly as https://${a.domainName}`],
      undo: UNDO_ADD,
      protect: protectNew(a.domainName, a.siteUser),
    }),
  }),
  defineTool({
    name: "clp_site_delete",
    kind: "clpctl",
    command: "site:delete",
    cls: "destructive",
    title: "Delete a site",
    summary:
      "Deletes a site and what CloudPanel keeps for it (clpctl site:delete --force): its files, databases, site user, vhost and certificate; CloudPanel's own page calls this permanent and non-recoverable. --force is passed because no terminal exists to type yes in; the human's typed confirmation is the protection. A protected domain cannot be deleted through this server. The site user and the databases go with the site even if they are listed under protect.siteUsers or protect.databases, so protect the domain of any site that must survive.",
    shape: { domainName },
    annotations: annotate(false, true, true),
    options: { domainName: req("domain") },
    flags: ["--force"],
    protectOptions: { domainName: "domain" },
    plan: (a) => ({
      command: "site:delete",
      options: [opt("domainName", a.domainName)],
      flags: ["--force"],
      summary: `DELETE the site ${a.domainName}`,
      effects: [
        `removes all files of the site (its home directory), its databases and its site user`,
        "removes the NGINX vhost and the certificate",
        "CloudPanel documents this as permanent: nothing is recoverable from the server",
      ],
      undo: "none; restore from a backup or snapshot",
      confirm: { target: a.domainName, noun: "domain" },
      protect: [{ kind: "domain", value: a.domainName }],
    }),
  }),
];
