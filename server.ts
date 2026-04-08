import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import express, { type NextFunction, type Request, type Response } from 'express';
import jwt from 'jsonwebtoken';
import { initDb } from './db.js';
import 'dotenv/config';
import type Database from 'better-sqlite3';

type JwtUser = {
  id: string;
  openid: string;
  is_vip: boolean;
  auth_type: 'login' | 'anonymous';
};

type AuthedRequest = Request & {
  user?: JwtUser;
};

type SessionResult = {
  openid?: string;
  anonymous_openid?: string;
  unionid?: string;
  session_key?: string;
};

type StoredUser = {
  id: string;
  openid: string | null;
  anonymous_openid: string | null;
  unionid: string | null;
  auth_type: 'login' | 'anonymous';
  is_vip: number;
  nickname: string | null;
  avatar_url: string | null;
  profile_authorized: number;
  profile_verified: number;
  app_id: string | null;
};

type StoredProgress = {
  user_id: string;
  unlocked_level: number;
  stars: string;
  milestone_stars: string;
  bonus_stars: number;
  win_streak: number;
};

const MINI_GAME_APP_ID =
  process.env.DOUYIN_APP_ID ||
  process.env.APP_ID ||
  process.env.TT_APP_ID ||
  'ttd4a0a21d4ac66d7702';
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const DOUYIN_APP_SECRET =
  process.env.DOUYIN_APP_SECRET ||
  process.env.APP_SECRET ||
  process.env.APPSECREAT ||
  process.env.DOUYIN_APPSECREAT ||
  '';
const DOUYIN_PAY_SALT = process.env.DOUYIN_PAY_SALT || process.env.PAY_SALT || '';
const IS_CLOUD = process.env.DOUYIN_CLOUD === 'true';
const DEFAULT_PORT = IS_CLOUD ? '8000' : '3000';
const PORT = Number.parseInt(process.env.PORT || DEFAULT_PORT, 10);
const PUBLIC_DIR = process.env.PUBLIC_DIR || path.join(process.cwd(), 'public');
const IS_DEV = process.env.NODE_ENV !== 'production' || !DOUYIN_APP_SECRET;

function safeLogBody(body: unknown) {
  if (!body || typeof body !== 'object') {
    return body;
  }
  const cloned = JSON.parse(JSON.stringify(body));
  if (cloned.code) cloned.code = '[masked]';
  if (cloned.anonymousCode) cloned.anonymousCode = '[masked]';
  if (cloned.signature) cloned.signature = '[masked]';
  if (cloned.rawData) cloned.rawData = '[masked]';
  if (cloned.encryptedData) cloned.encryptedData = '[masked]';
  if (cloned.iv) cloned.iv = '[masked]';
  return cloned;
}

function getRequestId(req: Request) {
  return (req as Request & { requestId?: string }).requestId || 'unknown';
}

function logWithRequest(req: Request, label: string, payload?: unknown) {
  const requestId = getRequestId(req);
  if (typeof payload === 'undefined') {
    console.log(`[req:${requestId}] ${label}`);
    return;
  }
  console.log(`[req:${requestId}] ${label}`, payload);
}

function tryResolveGatewayTarget(req: Request) {
  const candidates = [
    req.headers['x-tt-path'],
    req.headers['x-path'],
    req.headers['x-forwarded-uri'],
    req.headers['x-original-uri'],
    req.headers['x-envoy-original-path'],
    req.query.path,
    req.query.target,
    req.body && typeof req.body === 'object' ? req.body.path : undefined,
    req.body && typeof req.body === 'object' ? req.body.url : undefined,
  ];

  for (let i = 0; i < candidates.length; i += 1) {
    const value = candidates[i];
    if (typeof value === 'string' && value.startsWith('/')) {
      return value;
    }
  }

  return '';
}

function generatePaySign(params: Record<string, unknown>): string {
  const filtered = Object.entries(params)
    .filter(([key, value]) => key !== 'sign' && value !== null && value !== undefined && value !== '')
    .sort(([left], [right]) => left.localeCompare(right));

  const signStr = `${filtered.map(([key, value]) => `${key}=${value}`).join('&')}&salt=${DOUYIN_PAY_SALT}`;
  return crypto.createHash('md5').update(signStr, 'utf8').digest('hex');
}

function maskValue(value?: string | null) {
  if (!value) {
    return '';
  }
  if (value.length <= 8) {
    return value;
  }
  return `${value.slice(0, 4)}***${value.slice(-4)}`;
}

function buildUserResponse(user: StoredUser) {
  return {
    id: user.id,
    isVip: !!user.is_vip,
    authType: user.auth_type,
    hasOpenId: !!user.openid,
    hasAnonymousOpenId: !!user.anonymous_openid,
    openIdMasked: maskValue(user.openid),
    anonymousOpenIdMasked: maskValue(user.anonymous_openid),
    unionIdMasked: maskValue(user.unionid),
    appId: user.app_id || MINI_GAME_APP_ID,
    profileAuthorized: !!user.profile_authorized,
    profileVerified: !!user.profile_verified,
    profile: {
      nickName: user.nickname || '',
      avatarUrl: user.avatar_url || '',
    },
  };
}

function parseStars(raw: string | null | undefined) {
  if (!raw) {
    return [] as number[];
  }
  try {
    const stars = JSON.parse(raw);
    return Array.isArray(stars) ? stars : [];
  } catch (error) {
    return [];
  }
}

function getTotalStars(stars: number[], milestoneStars: number[], bonusStars: number) {
  return stars.length + milestoneStars.length + Math.max(0, bonusStars || 0);
}

function mergeProgressForUser(db: Database.Database, targetUserId: string, sourceUserId: string) {
  const targetProgress = db.prepare('SELECT * FROM progress WHERE user_id = ?').get(targetUserId) as StoredProgress | null;
  const sourceProgress = db.prepare('SELECT * FROM progress WHERE user_id = ?').get(sourceUserId) as StoredProgress | null;
  const targetStars = parseStars(targetProgress?.stars);
  const sourceStars = parseStars(sourceProgress?.stars);
  const targetMilestoneStars = parseStars(targetProgress?.milestone_stars);
  const sourceMilestoneStars = parseStars(sourceProgress?.milestone_stars);
  const mergedStars = Array.from(new Set([...targetStars, ...sourceStars])).sort((a, b) => a - b);
  const mergedMilestoneStars = Array.from(new Set([...targetMilestoneStars, ...sourceMilestoneStars])).sort((a, b) => a - b);
  const mergedBonusStars = (targetProgress?.bonus_stars || 0) + (sourceProgress?.bonus_stars || 0);
  const mergedUnlockedLevel = Math.max(targetProgress?.unlocked_level || 1, sourceProgress?.unlocked_level || 1);
  const mergedWinStreak = Math.max(targetProgress?.win_streak || 0, sourceProgress?.win_streak || 0);

  db.prepare(
    `INSERT INTO progress (user_id, unlocked_level, stars, milestone_stars, bonus_stars, win_streak, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
     ON CONFLICT(user_id) DO UPDATE SET
       unlocked_level = excluded.unlocked_level,
       stars = excluded.stars,
       milestone_stars = excluded.milestone_stars,
       bonus_stars = excluded.bonus_stars,
       win_streak = excluded.win_streak,
       updated_at = datetime('now')`
  ).run(targetUserId, mergedUnlockedLevel, JSON.stringify(mergedStars), JSON.stringify(mergedMilestoneStars), mergedBonusStars, mergedWinStreak);

  db.prepare('DELETE FROM progress WHERE user_id = ?').run(sourceUserId);
}

function verifyProfileSignature(rawData: string, sessionKey: string, signature: string) {
  const computed = crypto.createHash('sha1').update(`${rawData}${sessionKey}`, 'utf8').digest('hex');
  return computed === signature;
}

function decryptSensitiveData(encryptedData: string, sessionKey: string, iv: string) {
  const decipher = crypto.createDecipheriv(
    'aes-128-cbc',
    Buffer.from(sessionKey, 'base64'),
    Buffer.from(iv, 'base64'),
  );
  decipher.setAutoPadding(true);
  const decoded = Buffer.concat([
    decipher.update(Buffer.from(encryptedData, 'base64')),
    decipher.final(),
  ]);
  return JSON.parse(decoded.toString('utf8'));
}

async function fetchSession(code?: string, anonymousCode?: string): Promise<SessionResult> {
  const response = await fetch('https://developer.toutiao.com/api/apps/v2/jscode2session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      appid: MINI_GAME_APP_ID,
      secret: DOUYIN_APP_SECRET,
      code: code || '',
      anonymous_code: anonymousCode || '',
    }),
  });

  const json = await response.json();
  if (json.err_no !== 0) {
    throw new Error(`jscode2session failed: err_no=${json.err_no}, err_tips=${json.err_tips}`);
  }

  return json.data || {};
}

async function fetchSessionWithLog(req: Request, code?: string, anonymousCode?: string): Promise<SessionResult> {
  logWithRequest(req, '[auth] jscode2session.request', {
    hasCode: !!code,
    hasAnonymousCode: !!anonymousCode,
    appId: MINI_GAME_APP_ID,
    isDev: IS_DEV
  });

  const response = await fetch('https://developer.toutiao.com/api/apps/v2/jscode2session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      appid: MINI_GAME_APP_ID,
      secret: DOUYIN_APP_SECRET,
      code: code || '',
      anonymous_code: anonymousCode || '',
    }),
  });

  let json: any = null;
  try {
    json = await response.json();
  } catch (error) {
    logWithRequest(req, '[auth] jscode2session.invalid_json', {
      status: response.status,
      statusText: response.statusText,
      error: error instanceof Error ? error.message : String(error)
    });
    throw error;
  }

  logWithRequest(req, '[auth] jscode2session.response', {
    status: response.status,
    err_no: json && typeof json.err_no !== 'undefined' ? json.err_no : undefined,
    err_tips: json && json.err_tips ? json.err_tips : '',
    hasOpenId: !!(json && json.data && json.data.openid),
    hasAnonymousOpenId: !!(json && json.data && json.data.anonymous_openid),
    hasUnionId: !!(json && json.data && json.data.unionid),
    hasSessionKey: !!(json && json.data && json.data.session_key)
  });

  if (json.err_no !== 0) {
    throw new Error(`jscode2session failed: err_no=${json.err_no}, err_tips=${json.err_tips}`);
  }

  return json.data || {};
}

function upsertUserFromSession(
  db: Database.Database,
  session: SessionResult,
  appId?: string
) {
  const openid = session.openid || null;
  const anonymousOpenId = session.anonymous_openid || null;
  const unionid = session.unionid || null;
  const sessionKey = session.session_key || null;
  const authType: 'login' | 'anonymous' = openid ? 'login' : 'anonymous';

  const loginUser = (openid
    ? db.prepare('SELECT * FROM users WHERE openid = ?').get(openid)
    : null) as StoredUser | null;
  const anonymousUser = (anonymousOpenId
    ? db.prepare('SELECT * FROM users WHERE anonymous_openid = ?').get(anonymousOpenId)
    : null) as StoredUser | null;

  let user = loginUser || anonymousUser;

  if (loginUser && anonymousUser && loginUser.id !== anonymousUser.id) {
    mergeProgressForUser(db, loginUser.id, anonymousUser.id);
    db.prepare(
      `UPDATE users
       SET anonymous_openid = COALESCE(?, anonymous_openid),
           unionid = COALESCE(?, unionid),
           app_id = COALESCE(?, app_id),
           session_key = COALESCE(?, session_key),
           is_vip = MAX(is_vip, ?),
           updated_at = datetime('now'),
           last_login_at = datetime('now')
       WHERE id = ?`
    ).run(
      anonymousOpenId,
      unionid,
      appId || MINI_GAME_APP_ID,
      sessionKey,
      anonymousUser.is_vip,
      loginUser.id
    );
    db.prepare('DELETE FROM users WHERE id = ?').run(anonymousUser.id);
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(loginUser.id) as StoredUser;
  }

  if (!user) {
    const userId = crypto.randomUUID();
    db.prepare(
      `INSERT INTO users (
        id, openid, anonymous_openid, unionid, auth_type, app_id, session_key, created_at, updated_at, last_login_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), datetime('now'))`
    ).run(userId, openid, anonymousOpenId, unionid, authType, appId || MINI_GAME_APP_ID, sessionKey);
    db.prepare('INSERT INTO progress (user_id) VALUES (?)').run(userId);
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId) as StoredUser;
  } else {
    db.prepare(
      `UPDATE users
       SET openid = COALESCE(?, openid),
           anonymous_openid = COALESCE(?, anonymous_openid),
           unionid = COALESCE(?, unionid),
           auth_type = ?,
           app_id = COALESCE(?, app_id),
           session_key = COALESCE(?, session_key),
           updated_at = datetime('now'),
           last_login_at = datetime('now')
       WHERE id = ?`
    ).run(openid, anonymousOpenId, unionid, authType, appId || MINI_GAME_APP_ID, sessionKey, user.id);
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(user.id) as StoredUser;
  }

  return user!;
}

function upsertUserFromSessionWithLog(
  req: Request,
  db: Database.Database,
  session: SessionResult,
  appId?: string
) {
  logWithRequest(req, '[auth] upsert.begin', {
    appId: appId || MINI_GAME_APP_ID,
    hasOpenId: !!session.openid,
    hasAnonymousOpenId: !!session.anonymous_openid,
    hasUnionId: !!session.unionid,
    hasSessionKey: !!session.session_key
  });

  const openid = session.openid || null;
  const anonymousOpenId = session.anonymous_openid || null;
  const loginUser = (openid
    ? db.prepare('SELECT id, auth_type, is_vip FROM users WHERE openid = ?').get(openid)
    : null) as { id: string; auth_type: string; is_vip: number } | null;
  const anonymousUser = (anonymousOpenId
    ? db.prepare('SELECT id, auth_type, is_vip FROM users WHERE anonymous_openid = ?').get(anonymousOpenId)
    : null) as { id: string; auth_type: string; is_vip: number } | null;

  logWithRequest(req, '[auth] upsert.lookup', {
    loginUserId: loginUser ? loginUser.id : '',
    anonymousUserId: anonymousUser ? anonymousUser.id : '',
    willMerge: !!(loginUser && anonymousUser && loginUser.id !== anonymousUser.id)
  });

  let user: StoredUser;
  try {
    user = upsertUserFromSession(db, session, appId);
  } catch (error) {
    logWithRequest(req, '[auth] upsert.internal.failed', {
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : ''
    });
    throw error;
  }
  logWithRequest(req, '[auth] upsert.done', {
    userId: user.id,
    authType: user.auth_type,
    isVip: !!user.is_vip,
    hasOpenId: !!user.openid,
    hasAnonymousOpenId: !!user.anonymous_openid
  });
  return user;
}

async function startServer() {
  const app = express();
  const db = initDb();

  app.use(express.json({ limit: '1mb' }));
  app.use((req, res, next) => {
    const requestId = crypto.randomUUID().slice(0, 8);
    const startAt = Date.now();
    (req as Request & { requestId?: string }).requestId = requestId;
    console.log(`[req:${requestId}] -> ${req.method} ${req.path}`, safeLogBody(req.body));
    res.on('finish', () => {
      console.log(`[req:${requestId}] <- ${res.statusCode} ${req.method} ${req.path} ${Date.now() - startAt}ms`);
    });
    next();
  });

  if (IS_DEV) {
    app.use((req, _res, next) => {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
      next();
    });
  }

  app.use((req, res, next) => {
    if (!req.path.startsWith('/api/gateway/service/v1')) {
      return next();
    }

    const target = tryResolveGatewayTarget(req);
    console.log('[gateway] incoming local-dev proxy request:', {
      method: req.method,
      path: req.path,
      originalUrl: req.originalUrl,
      resolvedTarget: target || '',
      headers: req.headers,
      query: req.query,
    });

    if (!target) {
      return res.status(502).json({
        error: 'gateway target path missing',
        detail: 'Local dev proxy did not expose the original business path to the server',
      });
    }

    req.url = target;
    return next();
  });

  app.get('/ping', (_req, res) => {
    res.json({
      ok: true,
      service: 'light-refraction-server',
      env: process.env.NODE_ENV || 'development',
      appId: MINI_GAME_APP_ID,
    });
  });

  app.get('/v1/ping', (_req, res) => {
    res.json({ err_no: 0, message: 'pong' });
  });

  const authenticate = (req: AuthedRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: '未登录' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err || !decoded || typeof decoded === 'string') {
        console.warn(`[auth] token verify failed: ${err ? err.message : 'invalid decoded'}`);
        return res.status(403).json({ error: 'Token 无效或已过期' });
      }

      req.user = decoded as JwtUser;
      console.log(`[auth] user authenticated: id=${req.user.id}, authType=${req.user.auth_type}`);
      next();
    });
  };

  app.post('/api/auth/douyinLogin', async (req, res) => {
    const { code, anonymousCode, isLogin, appId } = req.body ?? {};
    logWithRequest(req, '[auth] douyinLogin.payload', {
      isLogin: !!isLogin,
      hasCode: !!code,
      hasAnonymousCode: !!anonymousCode,
      appId: appId || MINI_GAME_APP_ID,
      xTtOpenId: typeof req.headers['x-tt-openid'] === 'string' ? maskValue(req.headers['x-tt-openid']) : ''
    });
    if ((!code || typeof code !== 'string') && (!anonymousCode || typeof anonymousCode !== 'string')) {
      return res.status(400).json({ error: 'code 或 anonymousCode 至少传一个' });
    }

    let session: SessionResult;
    try {
      session = await fetchSessionWithLog(req, code, anonymousCode);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown error';
      logWithRequest(req, '[auth] douyinLogin.fetchSession.failed', {
        message,
        stack: error instanceof Error ? error.stack : ''
      });
      return res.status(500).json({ error: '登录失败，请稍后重试', detail: message });
    }

    try {
      const user = upsertUserFromSessionWithLog(req, db, session, appId);
      const token = jwt.sign(
        {
          id: user.id,
          openid: user.openid || user.anonymous_openid || '',
          is_vip: !!user.is_vip,
          auth_type: user.auth_type,
        },
        JWT_SECRET,
        { expiresIn: '30d' }
      );

      logWithRequest(req, '[auth] douyinLogin.success', {
        userId: user.id,
        authType: user.auth_type,
        isVip: !!user.is_vip,
        hasToken: !!token
      });

      return res.json({
        token,
        user: buildUserResponse(user),
        loginResult: {
          isLogin: !!isLogin,
          hasCode: !!code,
          hasAnonymousCode: !!anonymousCode,
        },
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown error';
      return res.status(500).json({ error: '用户初始化失败', detail: message });
    }
  });

  app.get('/api/auth/me', authenticate, async (req: AuthedRequest, res) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user!.id) as StoredUser | null;
    if (!user) {
      return res.status(404).json({ error: '用户不存在' });
    }
    return res.json({ user: buildUserResponse(user) });
  });

  app.post('/api/user/profile', authenticate, async (req: AuthedRequest, res) => {
    const { userInfo, rawData, signature, encryptedData, iv, appId } = req.body ?? {};
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user!.id) as (StoredUser & { session_key: string | null }) | null;
    if (!user) {
      return res.status(404).json({ error: '用户不存在' });
    }

    let profileVerified = false;
    let decryptedProfile: any = null;

    try {
      if (
        user.session_key &&
        typeof rawData === 'string' &&
        typeof signature === 'string' &&
        typeof encryptedData === 'string' &&
        typeof iv === 'string'
      ) {
        profileVerified = verifyProfileSignature(rawData, user.session_key, signature);
        if (profileVerified) {
          decryptedProfile = decryptSensitiveData(encryptedData, user.session_key, iv);
          if (decryptedProfile && decryptedProfile.watermark && typeof decryptedProfile.watermark === 'object') {
            const watermarkAppId = decryptedProfile.watermark.appid;
            if (watermarkAppId && watermarkAppId !== (appId || MINI_GAME_APP_ID)) {
              profileVerified = false;
            }
          }
        }
      }
    } catch (error) {
      profileVerified = false;
    }

    const nickname = userInfo && typeof userInfo.nickName === 'string' ? userInfo.nickName : user.nickname;
    const avatarUrl = userInfo && typeof userInfo.avatarUrl === 'string' ? userInfo.avatarUrl : user.avatar_url;

    db.prepare(
      `UPDATE users
       SET nickname = ?,
           avatar_url = ?,
           profile_authorized = 1,
           profile_verified = ?,
           profile_payload = ?,
           profile_raw_data = ?,
           app_id = COALESCE(?, app_id),
           last_profile_at = datetime('now'),
           updated_at = datetime('now')
       WHERE id = ?`
    ).run(
      nickname || null,
      avatarUrl || null,
      profileVerified ? 1 : 0,
      JSON.stringify(decryptedProfile || userInfo || {}),
      typeof rawData === 'string' ? rawData : null,
      appId || MINI_GAME_APP_ID,
      req.user!.id
    );

    const updatedUser = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user!.id) as StoredUser;
    return res.json({
      success: true,
      verified: profileVerified,
      user: buildUserResponse(updatedUser),
    });
  });

  app.get('/api/user/profile', authenticate, async (req: AuthedRequest, res) => {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user!.id) as StoredUser | null;
    if (!user) {
      return res.status(404).json({ error: '用户不存在' });
    }
    return res.json({ user: buildUserResponse(user) });
  });

  app.get('/api/user/progress', authenticate, async (req: AuthedRequest, res) => {
    const userId = req.user!.id;
    const progress = db.prepare('SELECT * FROM progress WHERE user_id = ?').get(userId) as {
      unlocked_level: number;
      stars: string;
      milestone_stars: string;
      bonus_stars: number;
      win_streak: number;
    } | null;
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId) as StoredUser | null;
    const stars = parseStars(progress?.stars);
    const milestoneStars = parseStars(progress?.milestone_stars);
    const bonusStars = progress?.bonus_stars || 0;

    return res.json({
      unlockedLevel: progress?.unlocked_level || 1,
      stars,
      milestoneStars,
      bonusStars,
      starCount: stars.length + milestoneStars.length + Math.max(0, bonusStars || 0),
      winStreak: progress?.win_streak || 0,
      isVip: !!user?.is_vip,
      user: user ? buildUserResponse(user) : null,
    });
  });

  app.post('/api/user/progress', authenticate, async (req: AuthedRequest, res) => {
    const { unlockedLevel, stars, milestoneStars, winStreak, bonusStars } = req.body ?? {};
    const userId = req.user!.id;
    const today = new Date().toISOString().split('T')[0];
    const existingProgress = db.prepare('SELECT * FROM progress WHERE user_id = ?').get(userId) as {
      unlocked_level: number;
      stars: string;
      milestone_stars: string;
      bonus_stars: number;
      win_streak: number;
    } | null;
    const existingStars = parseStars(existingProgress?.stars);
    const existingMilestoneStars = parseStars(existingProgress?.milestone_stars);
    const nextStars = Array.isArray(stars) ? stars : [];
    const mergedStars = Array.from(new Set([...existingStars, ...nextStars]))
      .map((item) => Number(item))
      .filter((item) => Number.isFinite(item))
      .sort((a, b) => a - b);
    const nextMilestoneStars = Array.isArray(milestoneStars) ? milestoneStars : [];
    const mergedMilestoneStars = Array.from(new Set([...existingMilestoneStars, ...nextMilestoneStars]))
      .map((item) => Number(item))
      .filter((item) => Number.isFinite(item))
      .sort((a, b) => a - b);
    const nextBonusStars = typeof bonusStars === 'number'
      ? Math.max(0, Math.floor(bonusStars))
      : (existingProgress?.bonus_stars || 0);
    const previousTotalStars = existingStars.length + existingMilestoneStars.length + Math.max(0, existingProgress?.bonus_stars || 0);
    const totalStars = mergedStars.length + mergedMilestoneStars.length + Math.max(0, nextBonusStars || 0);
    const earnedDelta = Math.max(0, totalStars - previousTotalStars);

    db.prepare(
      'UPDATE progress SET unlocked_level = MAX(COALESCE(?, unlocked_level), unlocked_level), stars = ?, milestone_stars = ?, bonus_stars = ?, win_streak = COALESCE(?, win_streak), updated_at = datetime(\'now\') WHERE user_id = ?'
    ).run(unlockedLevel, JSON.stringify(mergedStars), JSON.stringify(mergedMilestoneStars), nextBonusStars, winStreak, userId);

    db.prepare(
      `INSERT INTO rankings (user_id, total_stars, daily_stars, win_streak, last_updated_date)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(user_id) DO UPDATE SET
         daily_stars = CASE
           WHEN last_updated_date = excluded.last_updated_date THEN daily_stars + excluded.daily_stars
           ELSE excluded.daily_stars
         END,
         total_stars = excluded.total_stars,
         win_streak = MAX(rankings.win_streak, excluded.win_streak),
         last_updated_date = excluded.last_updated_date,
         updated_at = datetime('now')`
    ).run(userId, totalStars, earnedDelta, winStreak ?? 0, today);

    return res.json({
      success: true,
      stars: mergedStars,
      milestoneStars: mergedMilestoneStars,
      bonusStars: nextBonusStars,
      starCount: totalStars,
      winStreak: winStreak ?? (existingProgress?.win_streak || 0)
    });
  });

  app.get('/api/user/checkin', authenticate, async (req: AuthedRequest, res) => {
    const userId = req.user!.id;
    const today = new Date().toISOString().split('T')[0];
    const checkin = db.prepare('SELECT * FROM checkins WHERE user_id = ? AND checkin_date = ?').get(userId, today);
    return res.json({ checkedIn: !!checkin });
  });

  app.post('/api/user/checkin', authenticate, async (req: AuthedRequest, res) => {
    const userId = req.user!.id;
    const today = new Date().toISOString().split('T')[0];

    try {
      db.prepare('INSERT INTO checkins (user_id, checkin_date, stars_rewarded) VALUES (?, ?, 1)').run(userId, today);
      db.prepare(
        'UPDATE progress SET bonus_stars = COALESCE(bonus_stars, 0) + 1, updated_at = datetime(\'now\') WHERE user_id = ?'
      ).run(userId);

      const progress = db.prepare('SELECT * FROM progress WHERE user_id = ?').get(userId) as {
        stars: string;
        milestone_stars: string;
        bonus_stars: number;
        win_streak: number;
      } | null;
      const stars = parseStars(progress?.stars);
      const milestoneStars = parseStars(progress?.milestone_stars);
      const nextBonusStars = progress?.bonus_stars || 0;
      const totalStars = getTotalStars(stars, milestoneStars, nextBonusStars);

      db.prepare(
        `INSERT INTO rankings (user_id, total_stars, daily_stars, win_streak, last_updated_date)
         VALUES (?, ?, 1, ?, ?)
         ON CONFLICT(user_id) DO UPDATE SET
           daily_stars = CASE WHEN last_updated_date = excluded.last_updated_date THEN daily_stars + 1 ELSE 1 END,
           total_stars = excluded.total_stars,
           win_streak = MAX(rankings.win_streak, excluded.win_streak),
           last_updated_date = excluded.last_updated_date,
           updated_at = datetime('now')`
      ).run(userId, totalStars, progress?.win_streak || 0, today);

      return res.json({
        success: true,
        checkedIn: true,
        bonusStars: nextBonusStars,
        starCount: totalStars
      });
    } catch (error) {
      return res.status(400).json({ error: '今日已签到' });
    }
  });

  app.get('/api/rankings', async (req, res) => {
    const { type } = req.query;
    const today = new Date().toISOString().split('T')[0];

    let list = [];
    if (type === 'daily') {
      list = db.prepare(`
        SELECT u.nickname, u.avatar_url, r.daily_stars as score
        FROM rankings r
        JOIN users u ON r.user_id = u.id
        WHERE r.last_updated_date = ?
        ORDER BY r.daily_stars DESC LIMIT 50`).all(today);
    } else if (type === 'streak') {
      list = db.prepare(`
        SELECT u.nickname, u.avatar_url, r.win_streak as score
        FROM rankings r
        JOIN users u ON r.user_id = u.id
        ORDER BY r.win_streak DESC LIMIT 50`).all();
    } else {
      list = db.prepare(`
        SELECT u.nickname, u.avatar_url, r.total_stars as score
        FROM rankings r
        JOIN users u ON r.user_id = u.id
        ORDER BY r.total_stars DESC LIMIT 50`).all();
    }

    return res.json({ list });
  });

  app.post('/api/user/unlockAll', authenticate, async (req: AuthedRequest, res) => {
    const userId = req.user!.id;
    db.prepare('UPDATE users SET is_vip = 1, updated_at = datetime(\'now\') WHERE id = ?').run(userId);

    const dbUser = db.prepare('SELECT * FROM users WHERE id = ?').get(userId) as StoredUser | null;
    const token = jwt.sign(
      {
        id: userId,
        openid: dbUser?.openid || dbUser?.anonymous_openid || '',
        is_vip: true,
        auth_type: dbUser?.auth_type || 'anonymous',
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    return res.json({ success: true, token, user: dbUser ? buildUserResponse(dbUser) : null });
  });

  app.post('/api/user/adRecord', authenticate, async (req: AuthedRequest, res) => {
    const { adUnitId } = req.body ?? {};
    db.prepare('INSERT INTO ad_records (user_id, ad_unit_id, created_at) VALUES (?, ?, datetime(\'now\'))').run(req.user!.id, adUnitId);
    return res.json({ success: true });
  });

  app.post('/api/user/log', authenticate, async (req: AuthedRequest, res) => {
    const { action, details } = req.body ?? {};
    db.prepare('INSERT INTO operation_logs (user_id, action, details, created_at) VALUES (?, ?, ?, datetime(\'now\'))').run(req.user!.id, action, JSON.stringify(details || {}));
    return res.json({ success: true });
  });

  app.post('/api/pay/createOrder', authenticate, async (req: AuthedRequest, res) => {
    const { price, description } = req.body ?? {};
    if (!price || !description) {
      return res.status(400).json({ error: '参数缺失' });
    }

    const outOrderNo = `LR_${Date.now()}_${req.user!.id.slice(0, 8)}`;
    const totalAmount = Math.round(Number(price) * 100);

    const orderParams: Record<string, unknown> = {
      app_id: MINI_GAME_APP_ID,
      out_order_no: outOrderNo,
      total_amount: totalAmount,
      subject: description,
      body: description,
      valid_time: 3600,
    };
    orderParams.sign = generatePaySign(orderParams);

    try {
      const response = await fetch('https://developer.toutiao.com/api/apps/ecpay/v1/create_order', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(orderParams),
      });
      const json = await response.json();
      if (json.err_no !== 0) {
        throw new Error(`create order failed: ${json.err_tips}`);
      }

      const orderToken = json.data.order_token;
      db.prepare(
        'INSERT INTO orders (user_id, out_order_no, order_token, amount, status, created_at) VALUES (?, ?, ?, ?, ?, datetime(\'now\'))'
      ).run(req.user!.id, outOrderNo, orderToken, totalAmount, 'pending');

      return res.json({
        success: true,
        data: {
          order_token: orderToken,
          out_order_no: outOrderNo,
        },
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown error';
      return res.status(500).json({ error: '创建订单失败', detail: message });
    }
  });

  app.post('/api/pay/callback', async (req, res) => {
    const { timestamp, nonce, msg, msg_signature: signature } = req.body ?? {};
    const computedSign = generatePaySign({ timestamp, nonce, msg });
    if (computedSign !== signature) {
      return res.json({ err_no: -1, err_tips: '签名错误' });
    }

    let msgData: { cp_orderno?: string; payment_status?: number };
    try {
      msgData = JSON.parse(msg);
    } catch {
      return res.json({ err_no: -1, err_tips: '消息解析失败' });
    }

    const outOrderNo = msgData.cp_orderno;
    const paymentStatus = msgData.payment_status;
    if (outOrderNo && paymentStatus === 2) {
      db.prepare('UPDATE orders SET status = ?, paid_at = datetime(\'now\') WHERE out_order_no = ?').run('paid', outOrderNo);
      const order = db.prepare('SELECT user_id FROM orders WHERE out_order_no = ?').get(outOrderNo) as { user_id: string } | null;
      if (order?.user_id) {
      db.prepare('UPDATE users SET is_vip = 1, updated_at = datetime(\'now\') WHERE id = ?').run(order.user_id);
      }
    }
    return res.json({ err_no: 0 });
  });

  app.use(express.static(PUBLIC_DIR));
  app.get('*', (req, res) => {
    if (req.path.startsWith('/api')) {
      return res.status(404).json({ error: 'Not found' });
    }
    return res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
  });

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[server] light-refraction-server listening on 0.0.0.0:${PORT} (${IS_DEV ? 'dev' : 'production'})`);
  });
}

startServer().catch((error) => {
  console.error('[server] failed to start:', error);
  process.exit(1);
});
