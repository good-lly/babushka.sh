import { Hono } from "hono";
import { S3mini } from "s3mini";

type Bindings = {
  BABUSHKA_CONFIG: KVNamespace;
  ASSETS: Fetcher;
  BABUSHKA_STORAGE?: R2Bucket;
};

type StorageMode = "r2" | "s3";

type Config = {
  passwordHash: string;
  storageMode: StorageMode;
  s3Endpoint?: string;
  s3Bucket?: string;
  s3AccessKey?: string;
  s3SecretKey?: string;
  s3Region?: string;
};

const app = new Hono<{ Bindings: Bindings }>();

const sha256 = async (str: string): Promise<string> => {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(str),
  );
  return [...new Uint8Array(buf)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
};

const getConfig = async (kv: KVNamespace): Promise<Config | null> => {
  const config = await kv.get<Config>("config", "json");
  if (config && !config.storageMode) config.storageMode = "s3";
  return config;
};

const SESSION_TTL = 86400;

const hmacSign = async (payload: string, secret: string): Promise<string> => {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload),
  );
  return [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
};

const createSession = async (passwordHash: string): Promise<string> => {
  const expires = String(Date.now() + SESSION_TTL * 1000);
  const sig = await hmacSign(expires, passwordHash);
  return `${expires}.${sig}`;
};

const verifySession = async (
  token: string,
  passwordHash: string,
): Promise<boolean> => {
  const dot = token.indexOf(".");
  if (dot === -1) return false;
  const expires = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (Date.now() > Number(expires)) return false;
  const expected = await hmacSign(expires, passwordHash);
  return sig === expected;
};

const getSessionCookie = (cookieHeader: string | undefined): string | null => {
  const m = (cookieHeader ?? "").match(/(?:^|;\s*)session=([^;]+)/);
  return m?.[1] ?? null;
};

const setSessionCookie = (val: string, maxAge = SESSION_TTL) =>
  `session=${val}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

const serveAsset = async (env: Bindings, url: string, path: string) => {
  const res = await env.ASSETS.fetch(new URL(path, url));
  return new Response(res.body, {
    status: res.status,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
};

const isAuthed = async (
  cookieHeader: string | undefined,
  config: Config,
): Promise<boolean> => {
  const token = getSessionCookie(cookieHeader);
  return token ? verifySession(token, config.passwordHash) : false;
};

type StorageTestResult = { ok: boolean; error?: string };

const testStorage = async (
  config: Config,
  r2?: R2Bucket,
): Promise<StorageTestResult> => {
  if (config.storageMode === "r2") {
    if (!r2) return { ok: false, error: "R2 binding not configured" };
    try {
      await r2.list({ limit: 1 });
      return { ok: true };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : "R2 connection failed",
      };
    }
  }
  try {
    const s3 = new S3mini({
      accessKeyId: config.s3AccessKey!,
      secretAccessKey: config.s3SecretKey!,
      endpoint: config.s3Endpoint!,
      region: config.s3Region!,
    });
    const exists = await s3.bucketExists();
    return exists ? { ok: true } : { ok: false, error: "Bucket not found" };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : "Connection failed",
    };
  }
};

app.get("/", async (c) => {
  const config = await getConfig(c.env.BABUSHKA_CONFIG);
  if (!config) return serveAsset(c.env, c.req.url, "/setup.html");
  if (!(await isAuthed(c.req.header("Cookie"), config)))
    return serveAsset(c.env, c.req.url, "/login.html");
  return serveAsset(c.env, c.req.url, "/dashboard.html");
});

app.get("/api/capabilities", async (c) => {
  const configured = !!(await getConfig(c.env.BABUSHKA_CONFIG));
  return c.json({ r2Available: !!c.env.BABUSHKA_STORAGE, configured });
});

app.post("/api/setup", async (c) => {
  if (await getConfig(c.env.BABUSHKA_CONFIG))
    return c.json({ error: "Already configured" }, 403);

  const body = await c.req.json<Record<string, string>>();
  const { password, passwordConfirm, storageMode } = body;

  if (!password || password.length < 8)
    return c.json({ error: "Password must be at least 8 characters" }, 400);
  if (password !== passwordConfirm)
    return c.json({ error: "Passwords do not match" }, 400);

  const mode = storageMode as StorageMode;

  if (mode === "r2") {
    if (!c.env.BABUSHKA_STORAGE)
      return c.json({ error: "R2 binding not available" }, 400);
  } else if (mode === "s3") {
    const { s3Endpoint, s3Bucket, s3Region, s3AccessKey, s3SecretKey } = body;
    if (!s3Endpoint || !s3Bucket || !s3Region || !s3AccessKey || !s3SecretKey) {
      return c.json({ error: "All S3 fields are required" }, 400);
    }
  } else {
    return c.json({ error: "Invalid storage mode" }, 400);
  }

  const passwordHash = await sha256(password);
  const config: Config = {
    passwordHash,
    storageMode: mode,
    ...(mode === "s3" && {
      s3Endpoint: body.s3Endpoint,
      s3Bucket: body.s3Bucket,
      s3AccessKey: body.s3AccessKey,
      s3SecretKey: body.s3SecretKey,
      s3Region: body.s3Region,
    }),
  };

  await c.env.BABUSHKA_CONFIG.put("config", JSON.stringify(config));

  const session = await createSession(passwordHash);
  c.header("Set-Cookie", setSessionCookie(session));
  return c.json({ ok: true });
});

app.post("/api/login", async (c) => {
  const config = await getConfig(c.env.BABUSHKA_CONFIG);
  if (!config) return c.json({ error: "Not configured" }, 400);

  const { password } = await c.req.json<{ password: string }>();
  const hash = await sha256(password ?? "");

  if (hash !== config.passwordHash)
    return c.json({ error: "Invalid password" }, 401);

  const session = await createSession(config.passwordHash);
  c.header("Set-Cookie", setSessionCookie(session));
  return c.json({ ok: true });
});

app.get("/api/logout", (c) => {
  c.header("Set-Cookie", setSessionCookie("", 0));
  return c.redirect("/");
});

app.get("/api/config", async (c) => {
  const config = await getConfig(c.env.BABUSHKA_CONFIG);
  if (!config || !(await isAuthed(c.req.header("Cookie"), config))) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  if (config.storageMode === "r2") {
    return c.json({ storageMode: "r2" as const });
  }
  return c.json({
    storageMode: "s3" as const,
    s3Endpoint: config.s3Endpoint,
    s3Bucket: config.s3Bucket,
    s3Region: config.s3Region,
  });
});

app.get("/api/storage/test", async (c) => {
  const config = await getConfig(c.env.BABUSHKA_CONFIG);
  if (!config || !(await isAuthed(c.req.header("Cookie"), config))) {
    return c.json({ error: "Unauthorized" }, 401);
  }
  return c.json(await testStorage(config, c.env.BABUSHKA_STORAGE));
});

export default app;
