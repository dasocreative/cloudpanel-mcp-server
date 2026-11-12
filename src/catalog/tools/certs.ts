import * as z from "zod/v4";
import { domainListSchema } from "../../validate/schemas.ts";
import { annotate, defineTool, opt, optional, req, type ToolSpec } from "../define.ts";
import { domainName, fileProblem } from "./common.ts";

const certFile = (what: string) =>
  z.string().min(2).max(256).describe(
    `Absolute path of ${what} on the SERVER, in the certs/ subdirectory of one of the profile's file directories (clp_server_info shows the exact directories), ending in .key, .pem, .crt, .cer, .cert, .chain or .ca-bundle. The operator puts it there; this tool cannot upload.`,
  );

export const certTools: ToolSpec[] = [
  defineTool({
    name: "clp_lets_encrypt_install_certificate",
    kind: "clpctl",
    command: "lets-encrypt:install:certificate",
    cls: "write",
    title: "Issue a Let's Encrypt certificate",
    summary:
      "Issues and installs a Let's Encrypt certificate for a site (clpctl lets-encrypt:install:certificate). For www.example.com the certificate also covers example.com, and the other way round. Valid DNS records pointing at this server must exist for every name, or the issuance fails. Takes up to 10 minutes.",
    timeout: "letsEncrypt",
    shape: {
      domainName,
      subjectAlternativeName: domainListSchema
        .optional()
        .describe("Extra domain names for the same certificate (at most 20), each with valid DNS records."),
    },
    annotations: annotate(false, false, false, true),
    options: {
      domainName: req("domain"),
      subjectAlternativeName: optional("domainList"),
    },
    protectOptions: { domainName: "domain", subjectAlternativeName: "domain" },
    plan: (a) => {
      const extra = a.subjectAlternativeName;
      return {
        command: "lets-encrypt:install:certificate",
        options: [
          opt("domainName", a.domainName),
          ...(extra === undefined ? [] : [opt("subjectAlternativeName", extra.join(","))]),
        ],
        flags: [],
        summary: `Issue a Let's Encrypt certificate for ${a.domainName}${extra === undefined ? "" : ` and ${extra.join(", ")}`}`,
        effects: [
          "contacts Let's Encrypt and replaces the site's current certificate on success",
          "counts against Let's Encrypt rate limits",
        ],
        undo: "install another certificate with clp_site_install_certificate or the panel",
        protect: [a.domainName, ...(extra ?? [])].map((value) => ({ kind: "domain" as const, value })),
      };
    },
  }),
  defineTool({
    name: "clp_site_install_certificate",
    kind: "clpctl",
    command: "site:install:certificate",
    cls: "write",
    title: "Install a custom certificate on a site",
    summary:
      "Installs a certificate you already have (clpctl site:install:certificate, CloudPanel 2.3.0 and later). The private key, certificate and chain are files the operator already put in the certs/ subdirectory of the profile's file directories; root reads them.",
    shape: {
      domainName,
      privateKey: certFile("the private key file"),
      certificate: certFile("the certificate file"),
      certificateChain: certFile("the certificate chain file").optional(),
    },
    annotations: annotate(false, false, true),
    options: {
      domainName: req("domain"),
      privateKey: req("certPath"),
      certificate: req("certPath"),
      certificateChain: optional("certPath"),
    },
    protectOptions: { domainName: "domain" },
    check: (a, p) =>
      fileProblem("privateKey", "cert", String(a["privateKey"]), p) ??
      fileProblem("certificate", "cert", String(a["certificate"]), p) ??
      (a["certificateChain"] === undefined ? null : fileProblem("certificateChain", "cert", String(a["certificateChain"]), p)),
    plan: (a) => ({
      command: "site:install:certificate",
      options: [
        opt("domainName", a.domainName),
        opt("privateKey", a.privateKey),
        opt("certificate", a.certificate),
        ...(a.certificateChain === undefined ? [] : [opt("certificateChain", a.certificateChain)]),
      ],
      flags: [],
      summary: `Install the certificate ${a.certificate} (key ${a.privateKey}) on ${a.domainName}`,
      effects: [`replaces the current certificate of ${a.domainName}`, "reads the key and certificate files as root"],
      undo: "install the previous certificate again",
      protect: [{ kind: "domain", value: a.domainName }],
    }),
  }),
];
