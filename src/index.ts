import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { S3mini } from 's3mini';
import { cshake256 } from '@noble/hashes/sha3-addons.js';

type Bindings = {
  BABUSHKA_CONFIG: KVNamespace;
  ASSETS: Fetcher;
  BABUSHKA_STORAGE?: R2Bucket;
};

type StorageMode = 'r2' | 's3';

type Config = {
  passwordHash: string;
  passwordSalt: string;
  storageMode: StorageMode;
  lastLogin?: number;
  userId: string;
  machineIdList: string[];
  claudeKey?: string;
  ntfyEndpoint?: string;
  s3Endpoint?: string;
  s3Bucket?: string;
  s3AccessKey?: string;
  s3SecretKey?: string;
  s3Region?: string;
};

const app = new Hono<{ Bindings: Bindings }>();

const str2uint8 = (str: string): Uint8Array => new TextEncoder().encode(str);
const toHex = (arr: Uint8Array): string => [...arr].map(b => b.toString(16).padStart(2, '0')).join('');
const fromHex = (hex: string): Uint8Array => new Uint8Array(hex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
const MAGIC_CONST = str2uint8('babushka_sh_salt_v1');
const shakeLen = 128;
const randomBytes = (len: number): Uint8Array => {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return arr;
};
const letscShake256 = (data: Uint8Array, customData: Uint8Array, outputLength: number): Uint8Array => {
  if (outputLength <= 0) throw new Error('Output length must be positive');
  return cshake256(data, { personalization: customData, dkLen: outputLength });
};

const getConfig = async (kv: KVNamespace): Promise<Config | null> => {
  const config = await kv.get<Config>('config', 'json');
  if (config && !config.storageMode) config.storageMode = 's3';
  return config;
};

const SESSION_TTL = 24 * 60 * 60; // 24 hours in seconds
const COOKIE_OPTS = { path: '/', httpOnly: true, secure: true, sameSite: 'Strict' as const, maxAge: SESSION_TTL };

const hmacSign = async (payload: string, secret: string): Promise<string> => {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return toHex(new Uint8Array(sig));
};

const createSession = async (passwordHash: string): Promise<string> => {
  const expires = String(Date.now() + SESSION_TTL * 1000);
  const sig = await hmacSign(expires, passwordHash);
  return `${expires}.${sig}`;
};

const verifySession = async (token: string, passwordHash: string): Promise<boolean> => {
  const dot = token.indexOf('.');
  if (dot === -1) return false;
  const expires = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  if (Date.now() > Number(expires)) return false;
  const expected = await hmacSign(expires, passwordHash);
  return sig === expected;
};

const serveAsset = async (env: Bindings, url: string, path: string) => {
  const res = await env.ASSETS.fetch(new URL(path, url));
  return new Response(res.body, {
    status: res.status,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });
};

const isAuthed = async (token: string | undefined, config: Config): Promise<boolean> =>
  token ? verifySession(token, config.passwordHash) : false;

type StorageTestResult = { ok: boolean; error?: string };

const testStorage = async (config: Config, r2?: R2Bucket): Promise<StorageTestResult> => {
  if (config.storageMode === 'r2') {
    if (!r2) return { ok: false, error: 'R2 binding not configured' };
    try {
      await r2.list({ limit: 1 });
      return { ok: true };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : 'R2 connection failed',
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
    return exists ? { ok: true } : { ok: false, error: 'Bucket not found' };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : 'Connection failed',
    };
  }
};

app.get('/', async c => {
  const config = await getConfig(c.env.BABUSHKA_CONFIG);
  if (!config) return serveAsset(c.env, c.req.url, '/setup.html');
  if (!(await isAuthed(getCookie(c, 'session'), config))) return serveAsset(c.env, c.req.url, '/login.html');
  return serveAsset(c.env, c.req.url, '/dashboard.html');
});

app.get('/api/capabilities', async c => {
  const configured = !!(await getConfig(c.env.BABUSHKA_CONFIG));
  return c.json({ r2Available: !!c.env.BABUSHKA_STORAGE, configured });
});

app.post('/api/setup', async c => {
  if (await getConfig(c.env.BABUSHKA_CONFIG)) return c.json({ error: 'Already configured' }, 403);

  const body = await c.req.json<Record<string, string>>();
  const { password, passwordConfirm, storageMode } = body;

  if (!password || password.length < 8) return c.json({ error: 'Password must be at least 8 characters' }, 400);
  if (password !== passwordConfirm) return c.json({ error: 'Passwords do not match' }, 400);

  const mode = storageMode as StorageMode;

  if (mode === 'r2') {
    if (!c.env.BABUSHKA_STORAGE) return c.json({ error: 'R2 binding not available' }, 400);
  } else if (mode === 's3') {
    const { s3Endpoint, s3Bucket, s3Region, s3AccessKey, s3SecretKey } = body;
    if (!s3Endpoint || !s3Bucket || !s3Region || !s3AccessKey || !s3SecretKey) {
      return c.json({ error: 'All S3 fields are required' }, 400);
    }
  } else {
    return c.json({ error: 'Invalid storage mode' }, 400);
  }
  const salt = randomBytes(32);
  const passwordHash = toHex(letscShake256(str2uint8(password), new Uint8Array([...MAGIC_CONST, ...salt]), shakeLen));
  const config: Config = {
    passwordHash,
    passwordSalt: toHex(salt),
    userId: crypto.randomUUID(),
    machineIdList: [],
    storageMode: mode,
    ...(mode === 's3' && {
      s3Endpoint: body.s3Endpoint,
      s3Bucket: body.s3Bucket,
      s3AccessKey: body.s3AccessKey,
      s3SecretKey: body.s3SecretKey,
      s3Region: body.s3Region,
    }),
  };

  await c.env.BABUSHKA_CONFIG.put('config', JSON.stringify(config));

  const session = await createSession(passwordHash);
  setCookie(c, 'session', session, COOKIE_OPTS);
  return c.json({ ok: true });
});

app.post('/api/login', async c => {
  const config = await getConfig(c.env.BABUSHKA_CONFIG);
  if (!config) return c.json({ error: 'Not configured' }, 400);
  const { password } = await c.req.json<{ password: string }>();
  const salt = fromHex(config.passwordSalt);
  const hash = toHex(letscShake256(str2uint8(password), new Uint8Array([...MAGIC_CONST, ...salt]), shakeLen));
  if (hash !== config.passwordHash) return c.json({ error: 'Invalid password' }, 401);
  const session = await createSession(config.passwordHash);
  setCookie(c, 'session', session, COOKIE_OPTS);
  return c.json({ ok: true });
});

app.get('/api/logout', c => {
  deleteCookie(c, 'session', { path: '/', secure: true });
  return c.redirect('/');
});

app.get('/api/config', async c => {
  const config = await getConfig(c.env.BABUSHKA_CONFIG);
  if (!config || !(await isAuthed(getCookie(c, 'session'), config))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  if (config.storageMode === 'r2') {
    return c.json({ storageMode: 'r2' as const });
  }
  return c.json({
    storageMode: 's3' as const,
    s3Endpoint: config.s3Endpoint,
    s3Bucket: config.s3Bucket,
    s3Region: config.s3Region,
  });
});

app.get('/api/storage/test', async c => {
  const config = await getConfig(c.env.BABUSHKA_CONFIG);
  if (!config || !(await isAuthed(getCookie(c, 'session'), config))) {
    return c.json({ error: 'Unauthorized' }, 401);
  }
  return c.json(await testStorage(config, c.env.BABUSHKA_STORAGE));
});

export default app;
