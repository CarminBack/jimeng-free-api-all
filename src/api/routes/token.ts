import _ from 'lodash';

import Request from '@/lib/request/Request.ts';
import Response from '@/lib/response/Response.ts';
import { getTokenLiveStatus, getCredit } from '@/api/controllers/core.ts';
import { requireRequestTokens } from '@/lib/token-pool.ts';
import { keyPreview } from '@/lib/database.ts';
import logger from '@/lib/logger.ts';

export default {

    prefix: '/token',

    post: {

        '/check': async (request: Request) => {
            request
                .validate('body.token', _.isString)
            const live = await getTokenLiveStatus(request.body.token);
            return {
                live
            }
        },

        '/points': async (request: Request) => {
            request
                .validate('headers.authorization', _.isString)
            const tokens = requireRequestTokens(request.headers.authorization);
            const points = await Promise.all(tokens.map(async (token) => {
                return {
                    token: keyPreview(token.token),
                    points: await getCredit(token.token)
                }
            }))
            return points;
        }

    }

}
