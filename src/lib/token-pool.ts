import crypto from 'crypto';

import db, { keyPreview } from '@/lib/database.ts';
import { tokenSplit } from '@/api/controllers/core.ts';
import APIException from '@/lib/exceptions/APIException.ts';
import EX from '@/api/consts/exceptions.ts';

export type RequestToken = {
  id: number | null;
  token: string;
};

function apiKeyMatches(candidate: string, expected: string): boolean {
  const left = Buffer.from(candidate);
  const right = Buffer.from(expected);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

export function resolveRequestTokens(authorization: string): RequestToken[] {
  const configuredApiKey = process.env.JIMENG_API_KEY || '';
  const suppliedTokens = tokenSplit(authorization);

  // Preserve upstream behavior for local development unless pool mode is configured.
  if (!configuredApiKey) return suppliedTokens.map(token => ({ id: null, token }));
  if (suppliedTokens.length !== 1 || !apiKeyMatches(suppliedTokens[0], configuredApiKey)) return [];
  return db.getPoolTokensForUse();
}

export function requireRequestTokens(authorization: string): RequestToken[] {
  const configuredApiKey = process.env.JIMENG_API_KEY || '';
  const suppliedTokens = tokenSplit(authorization);
  if (!configuredApiKey) {
    if (suppliedTokens.length > 0) return suppliedTokens.map(token => ({ id: null, token }));
    throw new APIException(EX.API_REQUEST_PARAMS_INVALID, 'Authorization token is empty').setHTTPStatusCode(401);
  }
  if (suppliedTokens.length !== 1 || !apiKeyMatches(suppliedTokens[0], configuredApiKey)) {
    throw new APIException(EX.API_REQUEST_PARAMS_INVALID, 'API key is invalid').setHTTPStatusCode(401);
  }
  const tokens = db.getPoolTokensForUse();
  if (tokens.length === 0) {
    throw new APIException(EX.API_REQUEST_FAILED, 'No enabled account is available in the token pool').setHTTPStatusCode(503);
  }
  return tokens;
}

export function gatewayApiKeyPreview(): string | null {
  const key = process.env.JIMENG_API_KEY || '';
  return key ? keyPreview(key) : null;
}

export function recordRequestStart(token: RequestToken): void {
  if (token.id != null) db.reservePoolToken(token.id);
}

export function recordRequestSuccess(token: RequestToken): void {
  if (token.id != null) db.markPoolTokenUsed(token.id);
}

export function recordRequestFailure(token: RequestToken, error: unknown): void {
  if (token.id == null) return;
  const message = error instanceof Error ? error.message : String(error);
  db.markPoolTokenFailure(token.id, message);
}
