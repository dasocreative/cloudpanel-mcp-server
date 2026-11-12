import * as z from "zod/v4";
import {
  DENIED_APP_PORTS,
  MAX_DOMAIN_LENGTH,
  MAX_DOMAIN_LIST,
  RE,
  RELEASE_CHANNELS,
  RESERVED_DATABASES,
  RESERVED_DB_USERS,
  RESERVED_SITE_USERS,
  USER_ROLES,
  USER_STATUS,
  isPortAllowedAtAll,
  parsePurge,
} from "./patterns.ts";

/**
 * zod schemas built from the patterns. The messages never echo the offending value (it may be
 * hostile text that would travel back to the model).
 */

export const domainSchema = z
  .string()
  .min(1)
  .max(MAX_DOMAIN_LENGTH)
  .regex(
    RE.domain,
    'must be a lowercase DNS hostname: a-z 0-9 "-" and dots, at least two labels, no wildcard, no trailing dot (IDN in punycode)',
  );

export const domainListSchema = z.array(domainSchema).min(1).max(MAX_DOMAIN_LIST);

export const siteUserSchema = z
  .string()
  .min(1)
  .max(32)
  .regex(RE.siteUser, "must match ^[a-z][a-z0-9_-]{0,31}$")
  .refine((v) => !RESERVED_SITE_USERS.includes(v), "is a reserved system name");

export const dbNameSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(
    RE.dbName,
    'must start with a letter or digit and contain only letters, digits and "-" (no underscore: CloudPanel rejects it), at most 64',
  );

/** A database that a tool may delete or overwrite: never a system schema. */
export const userDbNameSchema = dbNameSchema.refine(
  (v) => !RESERVED_DATABASES.includes(v.toLowerCase()),
  "is a reserved system database",
);

export const dbUserSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(RE.dbUser, "must match ^[A-Za-z0-9_]{1,64}$")
  .refine((v) => !RESERVED_DB_USERS.includes(v.toLowerCase()), "is a reserved system account");

export const templateNameSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(
    RE.templateName,
    'must be 1 to 64 characters of A-Z a-z 0-9 space . _ -, starting with a letter or digit, with no trailing space',
  );

export const panelUserSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(
    RE.panelUser,
    'must start with a letter or digit and contain only letters, digits, ".", "_" and "-" (at most 64)',
  );

export const emailSchema = z
  .string()
  .min(3)
  .max(254)
  .regex(
    RE.email,
    'must be a conservative e-mail address (letters, digits, ". _ + -" before the @)',
  );

export const personNameSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(
    RE.person,
    'must be ASCII letters, spaces and "-" only (at most 64); transliterate other characters',
  );

export const timezoneSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(RE.timezone, "must look like UTC or Africa/Casablanca");

export const phpVersionSchema = z
  .string()
  .regex(RE.phpVersion, 'must look like "8.4" (CloudPanel decides which versions are installed)');
export const nodejsVersionSchema = z
  .string()
  .regex(RE.nodejsVersion, 'must be a major version such as "22"');
export const pythonVersionSchema = z
  .string()
  .regex(RE.pythonVersion, 'must look like "3.12" (it must be installed on the server)');

export const appPortSchema = z
  .number()
  .int()
  .refine(
    isPortAllowedAtAll,
    `must be an integer from 1024 to 65535 and not one of ${DENIED_APP_PORTS.join(", ")} (databases, caches, admin APIs, the panel)`,
  );

export const userRoleSchema = z.enum(USER_ROLES);
export const userStatusSchema = z.enum(USER_STATUS);
export const releaseChannelSchema = z.enum(RELEASE_CHANNELS);

export const fileModeSchema = z
  .string()
  .regex(RE.fileMode, "must be an octal mode such as 770 or 0660, without setuid, setgid or sticky bit and without world-write permission");

export const relativePathSchema = z
  .string()
  .min(1)
  .max(1100)
  .regex(
    RE.relativePath,
    'must be "." or a relative path below the home directory without ".." and without segments that start with "."',
  );

export const purgeSchema = z
  .string()
  .min(3)
  .max(400)
  .refine(
    (v) => parsePurge(v) !== null,
    'must be "all", a comma-separated list of at most 20 cache tags, or one http(s) URL without a port or query',
  );
