import _ from 'lodash';

import Request from '@/lib/request/Request.ts';
import Response from '@/lib/response/Response.ts';
import { recordRequestFailure, recordRequestStart, recordRequestSuccess, requireRequestTokens } from '@/lib/token-pool.ts';
import { createCompletion, createCompletionStream } from '@/api/controllers/chat.ts';

export default {

    prefix: '/v1/chat',

    post: {

        '/completions': async (request: Request) => {
            request
                .validate('body.model', v => _.isUndefined(v) || _.isString(v))
                .validate('body.messages', _.isArray)
                .validate('headers.authorization', _.isString)
            const tokens = requireRequestTokens(request.headers.authorization);
            const selectedToken = tokens[0];
            const token = selectedToken.token;
            recordRequestStart(selectedToken);
            const { model, messages, stream } = request.body;
            try {
                if (stream) {
                    const streamResponse = await createCompletionStream(messages, token, model);
                    recordRequestSuccess(selectedToken);
                    return new Response(streamResponse, {
                        type: "text/event-stream"
                    });
                }
                const response = await createCompletion(messages, token, model);
                recordRequestSuccess(selectedToken);
                return response;
            } catch (error) {
                recordRequestFailure(selectedToken, error);
                throw error;
            }
        }

    }

}
