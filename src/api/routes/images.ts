import _ from "lodash";

import Request from "@/lib/request/Request.ts";
import { DEFAULT_MODEL, generateImagesWithRetry } from "@/api/controllers/images.ts";
import util from "@/lib/util.ts";
import db from "@/lib/database.ts";
import { recordRequestFailure, recordRequestStart, recordRequestSuccess, requireRequestTokens } from "@/lib/token-pool.ts";

export default {
  prefix: "/v1/images",

  post: {
    "/generations": async (request: Request) => {
      request
        .validate("body.model", v => _.isUndefined(v) || _.isString(v))
        .validate("body.prompt", _.isString)
        .validate("body.negative_prompt", v => _.isUndefined(v) || _.isString(v))
        .validate("body.ratio", v => _.isUndefined(v) || _.isString(v))
        .validate("body.resolution", v => _.isUndefined(v) || _.isString(v))
        .validate("body.sample_strength", v => _.isUndefined(v) || _.isFinite(v))
        .validate("body.response_format", v => _.isUndefined(v) || _.isString(v))
        .validate("body.size", v => _.isUndefined(v) || _.isString(v))
        .validate("body.quality", v => _.isUndefined(v) || _.isString(v))
        .validate("body.filePath", v => _.isUndefined(v) || _.isString(v))
        .validate("headers.authorization", _.isString);
      const tokens = requireRequestTokens(request.headers.authorization);
      const selectedToken = tokens[0];
      const token = selectedToken.token;
      recordRequestStart(selectedToken);
      const {
        model = DEFAULT_MODEL,
        prompt,
        negative_prompt: negativePrompt,
        ratio,
        resolution,
        sample_strength: sampleStrength,
        response_format,
        size,
        quality,
        filePath: bodyFilePath,
      } = request.body;

      const openAISizeRatios: Record<string, string> = {
        "1024x1024": "1:1",
        "1792x1024": "16:9",
        "1024x1792": "9:16",
      };
      const requestedRatio = ratio || openAISizeRatios[size];
      const requestedResolution = resolution || (quality === "hd" ? "4k" : undefined);
      
      // 处理文件上传 (multipart/form-data)
      let filePath = bodyFilePath;
      // @ts-ignore
      const files = request.files || {};
      // 检查是否有上传的文件
      if (!filePath && !_.isEmpty(files)) {
        const fileKey = Object.keys(files)[0];
        const file = files[fileKey];
        if (file) {
            filePath = file.filepath || file.path;
        }
      }

      const responseFormat = _.defaultTo(response_format, "url");
      let imageUrls: string[];
      try {
        imageUrls = await generateImagesWithRetry(model, prompt, {
          ratio: requestedRatio,
          resolution: requestedResolution,
          sampleStrength,
          negativePrompt,
          filePath,
        }, token);
        recordRequestSuccess(selectedToken);
      } catch (error) {
        recordRequestFailure(selectedToken, error);
        throw error;
      }
      
      // 记录统计和媒体
      try {
        db.recordCall(token, model, 0);
        imageUrls.forEach(url => {
          if (url) db.saveMedia('image', url, model, prompt, token);
        });
      } catch (e) {
        // 忽略数据库错误，不影响主流程
      }
      
      let data = [];
      if (responseFormat == "b64_json") {
        data = (
          await Promise.all(imageUrls.map((url) => util.fetchFileBASE64(url)))
        ).map((b64) => ({ b64_json: b64 }));
      } else {
        data = imageUrls.map((url) => ({
          url,
        }));
      }
      return {
        created: util.unixTimestamp(),
        data,
      };
    },
  },
};
