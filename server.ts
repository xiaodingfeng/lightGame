import crypto from 'node:crypto';
import path from 'node:path';
import express, { type NextFunction, type Request, type Response } from 'express';
import jwt from 'jsonwebtoken';
import { initDb } from './db.js';
import 'dotenv/config';

type JwtUser = {
  id: string;
  openid: string;
  is_vip: boolean;
};

type AuthedRequest = Request & {
  user?: JwtUser;
};

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const DOUYIN_APP_ID = process.env.DOUYIN_APP_ID || '';
const DOUYIN_APP_SECRET = process.env.DOUYIN_APP_SECRET || '';
const DOUYIN_PAY_SALT = process.env.DOUYIN_PAY_SALT || '';
const IS_CLOUD = process.env.DOUYIN_CLOUD === 'true';
const DEFAULT_PORT = IS_CLOUD ? '8000' : '3000';
const PORT = Number.parseInt(process.env.PORT || DEFAULT_PORT, 10);
const PUBLIC_DIR = process.env.PUBLIC_DIR || path.join(process.cwd(), 'public');
const IS_DEV = process.env.NODE_ENV !== 'production' || !DOUYIN_APP_SECRET;

function generatePaySign(params: Record<string, unknown>): string {
  const filtered = Object.entries(params)
    .filter(([key, value]) => key !== 'sign' && value !== null && value !== undefined && value !== '')
    .sort(([left], [right]) => left.localeCompare(right));

  const signStr = `${filtered.map(([key, value]) => `${key}=${value}`).join('&')}&salt=${DOUYIN_PAY_SALT}`;
  return crypto.createHash('md5').update(signStr, 'utf8').digest('hex');
}

async function fetchOpenId(code: string): Promise<string> {
  const response = await fetch('https://developer.toutiao.com/api/apps/v2/jscode2session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      appid: DOUYIN_APP_ID,
      secret: DOUYIN_APP_SECRET,
      code,
      anonymous_code: '',
    }),
  });

  const json = await response.json();
  if (json.err_no !== 0) {
    throw new Error(`jscode2session failed: err_no=${json.err_no}, err_tips=${json.err_tips}`);
  }

  return json.data.openid;
}

async function startServer() {
  const app = express();
  const db = await initDb();

  app.use(express.json());

  if (IS_DEV) {
    app.use((req, _res, next) => {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
      next();
    });
  }

  app.get('/ping', (_req, res) => {
    res.json({
      ok: true,
      service: 'light-refraction-server',
      env: process.env.NODE_ENV || 'development',
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
        return res.status(403).json({ error: 'Token 无效或已过期' });
      }

      req.user = decoded as JwtUser;
      next();
    });
  };

  app.post('/api/auth/douyinLogin', async (req, res) => {
    const { code } = req.body ?? {};
    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'code 不能为空' });
    }

    let openid: string;

    try {
      if (IS_DEV || code.startsWith('mock_')) {
        openid = `mock_openid_${crypto.createHash('md5').update(code).digest('hex').slice(0, 16)}`;
        console.log(`[auth] mock login, openid=${openid}`);
      } else {
        openid = await fetchOpenId(code);
        console.log(`[auth] douyin login, openid=${openid}`);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown error';
      console.error('[auth] failed to fetch openid:', message);
      return res.status(500).json({ error: '登录失败，请稍后重试' });
    }

    let user = await db.get<{ id: string; openid: string; is_vip: number }>(
      'SELECT * FROM users WHERE openid = ?',
      [openid]
    );

    if (!user) {
      const userId = crypto.randomUUID();
      await db.run(
        'INSERT INTO users (id, openid, created_at) VALUES (?, ?, datetime("now"))',
        [userId, openid]
      );
      await db.run('INSERT INTO progress (user_id) VALUES (?)', [userId]);
      user = { id: userId, openid, is_vip: 0 };
      console.log(`[db] created user ${userId}`);
    }

    const token = jwt.sign(
      { id: user.id, openid: user.openid, is_vip: !!user.is_vip },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    return res.json({
      token,
      user: {
        id: user.id,
        is_vip: !!user.is_vip,
      },
    });
  });

  app.get('/api/user/progress', authenticate, async (req: AuthedRequest, res) => {
    const userId = req.user!.id;
    const progress = await db.get<{ unlocked_level: number; stars: string }>(
      'SELECT * FROM progress WHERE user_id = ?',
      [userId]
    );
    const user = await db.get<{ is_vip: number }>('SELECT is_vip FROM users WHERE id = ?', [userId]);

    return res.json({
      unlockedLevel: progress?.unlocked_level || 1,
      stars: JSON.parse(progress?.stars || '[]'),
      isVip: !!user?.is_vip,
    });
  });

  app.post('/api/user/progress', authenticate, async (req: AuthedRequest, res) => {
    const { unlockedLevel, stars } = req.body ?? {};
    await db.run(
      'UPDATE progress SET unlocked_level = ?, stars = ?, updated_at = datetime("now") WHERE user_id = ?',
      [unlockedLevel, JSON.stringify(stars ?? []), req.user!.id]
    );
    return res.json({ success: true });
  });

  app.post('/api/user/unlockAll', authenticate, async (req: AuthedRequest, res) => {
    const user = req.user!;
    await db.run('UPDATE users SET is_vip = 1 WHERE id = ?', [user.id]);

    const token = jwt.sign(
      { id: user.id, openid: user.openid, is_vip: true },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    return res.json({ success: true, token });
  });

  app.post('/api/user/adRecord', authenticate, async (req: AuthedRequest, res) => {
    const { adUnitId } = req.body ?? {};
    await db.run(
      'INSERT INTO ad_records (user_id, ad_unit_id, created_at) VALUES (?, ?, datetime("now"))',
      [req.user!.id, adUnitId]
    );
    return res.json({ success: true });
  });

  app.post('/api/user/log', authenticate, async (req: AuthedRequest, res) => {
    const { action, details } = req.body ?? {};
    await db.run(
      'INSERT INTO operation_logs (user_id, action, details, created_at) VALUES (?, ?, ?, datetime("now"))',
      [req.user!.id, action, JSON.stringify(details || {})]
    );
    return res.json({ success: true });
  });

  app.post('/api/pay/createOrder', authenticate, async (req: AuthedRequest, res) => {
    const { price, description } = req.body ?? {};

    if (!price || !description) {
      return res.status(400).json({ error: '参数缺失' });
    }

    const outOrderNo = `LR_${Date.now()}_${req.user!.id.slice(0, 8)}`;
    const totalAmount = Math.round(Number(price) * 100);

    if (IS_DEV) {
      await db.run(
        'INSERT INTO orders (user_id, out_order_no, amount, status, created_at) VALUES (?, ?, ?, ?, datetime("now"))',
        [req.user!.id, outOrderNo, totalAmount, 'mock']
      );

      return res.json({
        success: true,
        data: {
          order_token: `mock_token_${outOrderNo}`,
          out_order_no: outOrderNo,
        },
      });
    }

    const orderParams: Record<string, unknown> = {
      app_id: DOUYIN_APP_ID,
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

      await db.run(
        'INSERT INTO orders (user_id, out_order_no, order_token, amount, status, created_at) VALUES (?, ?, ?, ?, ?, datetime("now"))',
        [req.user!.id, outOrderNo, orderToken, totalAmount, 'pending']
      );

      return res.json({
        success: true,
        data: {
          order_token: orderToken,
          out_order_no: outOrderNo,
        },
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'unknown error';
      console.error('[pay] failed to create order:', message);
      return res.status(500).json({ error: '创建订单失败', detail: message });
    }
  });

  app.post('/api/pay/callback', async (req, res) => {
    const { timestamp, nonce, msg, msg_signature: signature } = req.body ?? {};
    const computedSign = generatePaySign({ timestamp, nonce, msg });

    if (computedSign !== signature) {
      console.error('[pay.callback] invalid signature');
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
    console.log(`[pay.callback] order=${outOrderNo}, payment_status=${paymentStatus}`);

    if (outOrderNo && paymentStatus === 2) {
      await db.run(
        'UPDATE orders SET status = ?, paid_at = datetime("now") WHERE out_order_no = ?',
        ['paid', outOrderNo]
      );

      const order = await db.get<{ user_id: string }>(
        'SELECT user_id FROM orders WHERE out_order_no = ?',
        [outOrderNo]
      );

      if (order?.user_id) {
        await db.run('UPDATE users SET is_vip = 1 WHERE id = ?', [order.user_id]);
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
    console.log(`[server] static directory: ${PUBLIC_DIR}`);
    if (IS_CLOUD) {
      console.log('[server] running in Douyin Cloud compatible mode');
    }
  });
}

startServer().catch((error) => {
  console.error('[server] failed to start:', error);
  process.exit(1);
});
