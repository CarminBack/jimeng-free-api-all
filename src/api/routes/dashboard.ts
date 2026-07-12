import Request from '@/lib/request/Request.ts';
import Response from '@/lib/response/Response.ts';
import db from '@/lib/database.ts';
import { getCredit, getTokenLiveStatus } from '@/api/controllers/core.ts';
import { gatewayApiKeyPreview } from '@/lib/token-pool.ts';

const loginAttempts = new Map<string, { count: number; resetAt: number }>();

function adminUserId(request: Request): number | null {
  const sessionId = request.headers.cookie?.match(/session=([^;]+)/)?.[1];
  return sessionId ? db.validateSession(sessionId) : null;
}

function requireAdmin(request: Request): number | Response {
  return adminUserId(request) || new Response({ error: '未登录' }, { statusCode: 401 });
}

async function checkPoolToken(id: number) {
  const token = db.getPoolTokenSecret(id);
  if (!token) return new Response({ error: '账号不存在' }, { statusCode: 404 });
  try {
    const live = await getTokenLiveStatus(token);
    if (!live) {
      db.recordPoolTokenCheck(id, false, null, 'Session 已失效');
      return { id, live: false, points: null };
    }
    const credit = await getCredit(token);
    db.recordPoolTokenCheck(id, true, credit.totalCredit ?? null);
    return { id, live: true, points: credit.totalCredit ?? null };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    db.recordPoolTokenCheck(id, false, null, message);
    return { id, live: false, points: null, error: message };
  }
}

export default {
  prefix: '/dashboard',

  get: {
    // 检查是否需要初始化设置
    '/status': async (request: Request) => {
      return {
        setupComplete: db.isSetupComplete()
      };
    },

    // 获取统计数据
    '/stats': async (request: Request) => {
      const auth = requireAdmin(request);
      if (Response.isInstance(auth)) return auth;
      return db.getStats();
    },

    '/config': async (request: Request) => {
      const auth = requireAdmin(request);
      if (Response.isInstance(auth)) return auth;
      const tokens = db.listPoolTokens();
      return {
        apiBaseUrl: `${request.headers['x-forwarded-proto'] || 'https'}://${request.headers.host || ''}`,
        apiKeyPreview: gatewayApiKeyPreview(),
        poolConfigured: db.isTokenPoolConfigured(),
        totalAccounts: tokens.length,
        enabledAccounts: tokens.filter(token => token.enabled).length,
        healthyAccounts: tokens.filter(token => token.enabled && token.status === 'healthy').length
      };
    },

    '/tokens': async (request: Request) => {
      const auth = requireAdmin(request);
      if (Response.isInstance(auth)) return auth;
      return db.listPoolTokens();
    },

    // 获取日志
    '/logs': async (request: Request) => {
      const auth = requireAdmin(request);
      if (Response.isInstance(auth)) return auth;
      const level = request.query.level as string;
      const limit = parseInt(request.query.limit as string) || 100;
      return db.getLogs(level, limit);
    },

    // 获取媒体列表（分页）
    '/media': async (request: Request) => {
      const auth = requireAdmin(request);
      if (Response.isInstance(auth)) return auth;
      const page = parseInt(request.query.page as string) || 1;
      const limit = parseInt(request.query.limit as string) || 20;
      const type = request.query.type as string;
      return db.getMedia(page, limit, type);
    },

    // 获取指定Key的积分
    '/credits': async (request: Request) => {
      const auth = requireAdmin(request);
      if (Response.isInstance(auth)) return auth;
      const key = request.query.key as string;
      if (!key) {
        return { error: '缺少Key参数' };
      }
      try {
        const credits = await getCredit(key);
        return credits;
      } catch (e) {
        return { error: '查询失败', message: e.message };
      }
    }
  },

  post: {
    // 初始化设置账号密码
    '/setup': async (request: Request) => {
      if (db.isSetupComplete()) {
        return new Response({ error: '已完成初始化设置' }, { statusCode: 400 });
      }
      const { username, password } = request.body;
      if (!username || !password) {
        return new Response({ error: '用户名和密码不能为空' }, { statusCode: 400 });
      }
      if (password.length < 12) {
        return new Response({ error: '密码长度至少12位' }, { statusCode: 400 });
      }
      db.createUser(username, password);
      return { success: true, message: '设置成功' };
    },

    // 登录
    '/login': async (request: Request) => {
      const { username, password } = request.body;
      const attemptKey = request.remoteIP || 'unknown';
      const now = Date.now();
      const attempt = loginAttempts.get(attemptKey);
      if (attempt && attempt.resetAt > now && attempt.count >= 5) {
        return new Response({ error: '登录尝试过多，请15分钟后再试' }, { statusCode: 429 });
      }
      const userId = db.validateUser(username, password);
      if (!userId) {
        loginAttempts.set(attemptKey, {
          count: attempt && attempt.resetAt > now ? attempt.count + 1 : 1,
          resetAt: attempt && attempt.resetAt > now ? attempt.resetAt : now + 15 * 60 * 1000
        });
        return new Response({ error: '用户名或密码错误' }, { statusCode: 401 });
      }
      loginAttempts.delete(attemptKey);
      const sessionId = db.createSession(userId);
      const secure = process.env.NODE_ENV === 'production' || request.headers['x-forwarded-proto'] === 'https';
      return new Response(
        { success: true },
        { 
          statusCode: 200,
          headers: { 'Set-Cookie': `session=${sessionId}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400${secure ? '; Secure' : ''}` }
        }
      );
    },

    '/tokens': async (request: Request) => {
      const auth = requireAdmin(request);
      if (Response.isInstance(auth)) return auth;
      const name = String(request.body.name || '').trim();
      const token = String(request.body.token || '').trim();
      if (!name || !token) return new Response({ error: '账号名称和 Session ID 不能为空' }, { statusCode: 400 });
      if (token.length < 16) return new Response({ error: 'Session ID 格式不正确' }, { statusCode: 400 });
      const id = db.addPoolToken(name, token);
      return new Response({ success: true, id }, { statusCode: 201 });
    },

    '/tokens/:id/check': async (request: Request) => {
      const auth = requireAdmin(request);
      if (Response.isInstance(auth)) return auth;
      return checkPoolToken(Number(request.params.id));
    },

    '/tokens/check-all': async (request: Request) => {
      const auth = requireAdmin(request);
      if (Response.isInstance(auth)) return auth;
      const results = [];
      for (const token of db.listPoolTokens()) {
        results.push(await checkPoolToken(token.id));
      }
      return { success: true, results };
    },

    // 登出
    '/logout': async (request: Request) => {
      const sessionId = request.headers.cookie?.match(/session=([^;]+)/)?.[1];
      if (sessionId) {
        db.deleteSession(sessionId);
      }
      return new Response(
        { success: true },
        { 
          statusCode: 200,
          headers: { 'Set-Cookie': 'session=; Path=/; HttpOnly; Max-Age=0' }
        }
      );
    },

    // 修改密码
    '/password': async (request: Request) => {
      const sessionId = request.headers.cookie?.match(/session=([^;]+)/)?.[1];
      const userId = sessionId ? db.validateSession(sessionId) : null;
      if (!userId) {
        return new Response({ error: '未登录' }, { statusCode: 401 });
      }
      const { newPassword } = request.body;
      if (!newPassword || newPassword.length < 12) {
        return new Response({ error: '密码长度至少12位' }, { statusCode: 400 });
      }
      db.changePassword(userId, newPassword);
      return { success: true, message: '密码修改成功' };
    }
  },

  patch: {
    '/tokens/:id': async (request: Request) => {
      const auth = requireAdmin(request);
      if (Response.isInstance(auth)) return auth;
      const updated = db.updatePoolToken(Number(request.params.id), {
        name: typeof request.body.name === 'string' ? request.body.name : undefined,
        token: typeof request.body.token === 'string' ? request.body.token : undefined,
        enabled: typeof request.body.enabled === 'boolean' ? request.body.enabled : undefined
      });
      return updated ? { success: true } : new Response({ error: '账号不存在' }, { statusCode: 404 });
    }
  },

  delete: {
    // 清理日志
    '/logs': async (request: Request) => {
      const sessionId = request.headers.cookie?.match(/session=([^;]+)/)?.[1];
      if (!sessionId || !db.validateSession(sessionId)) {
        return new Response({ error: '未登录' }, { statusCode: 401 });
      }
      db.clearLogs();
      return { success: true, message: '日志已清理' };
    },

    '/tokens/:id': async (request: Request) => {
      const auth = requireAdmin(request);
      if (Response.isInstance(auth)) return auth;
      return db.deletePoolToken(Number(request.params.id))
        ? { success: true }
        : new Response({ error: '账号不存在' }, { statusCode: 404 });
    }
  }
};
