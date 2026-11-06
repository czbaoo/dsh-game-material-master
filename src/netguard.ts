/**
 * 出站网络请求的集中安全护栏。
 *
 * 背景：本插件对外发请求分两类——
 *   1. **带凭据的 API 调用**（`Authorization` / `X-Api-Key` / `Cookie`）：
 *      默认 `redirect: "follow"` 会把凭据原样转发到**任意**重定向目标，造成
 *      密钥 / 会话泄露（SSRF 式凭据外泄）。ToAPIs 模块已经用 `redirect: "error"`
 *      规避，这里把同一约束推广到所有提供商（见 `SAFE_REDIRECT`）。
 *   2. **下载请求**（从 API 返回的 URL 拉取结果，不带凭据）：默认同样会跟随
 *      重定向，可能被（被篡改的）响应引到内网地址做 SSRF。`fetchWithSafeRedirect`
 *      只接受 http(s)、逐跳校验、拒绝私有 / 内网主机，与 `toapis.downloadToapis`
 *      同一思路。
 */

/** 匹配私有 / 链路本地 / 环回 / 唯一本地地址（IPv4 与 IPv6）。 */
const PRIVATE_HOST =
  /^(localhost|127\.|10\.|192\.168\.|169\.254\.|0\.|::1?$|\[::|fc|fd|fe[89ab]|172\.(1[6-9]|2\d|3[01])\.)/iu;

/**
 * 校验一个 URL 只能落到对外可达的 http(s) 主机。
 *
 * - `allowHttp=false`（默认）：只接受 `https:`，避免明文传输被中间人篡改。
 * - `allowLocal=false`（默认）：拒绝环回 / 私有 / 链路本地地址，挡掉 SSRF。
 */
export function assertSafeUrl(
  input: string | URL,
  options: { allowHttp?: boolean; allowLocal?: boolean } = {},
): URL {
  const url = typeof input === "string" ? new URL(input) : new URL(input.href);
  if (url.protocol !== "https:" && !(options.allowHttp === true && url.protocol === "http:")) {
    throw new Error(`只允许 http(s) 地址，拒绝 ${url.protocol}//${url.host}`);
  }
  if (options.allowLocal !== true && PRIVATE_HOST.test(url.hostname)) {
    throw new Error(`拒绝私有 / 内网地址：${url.hostname}`);
  }
  return url;
}

/**
 * 给**带凭据**的 `fetch` 用的重定向策略：遇到任何重定向直接报错，
 * 绝不把 `Authorization` / `X-Api-Key` / `Cookie` 转发到重定向目标。
 *
 * 用法：`fetch(url, { ...init, redirect: SAFE_REDIRECT })`。
 */
export const SAFE_REDIRECT = "error" as const;

/**
 * 带逐跳校验的重定向跟随，用于**不带凭据**的下载。
 *
 * 每跳都要求 http(s) 且不能是私有 / 内网主机，避免被（被篡改的）响应引去打内网。
 * 与 `toapis.downloadToapis` 的区别：下载场景常有 CDN 302，所以这里允许 https 公网
 * 重定向，而不是像凭据请求那样一律拒绝。
 */
export async function fetchWithSafeRedirect(input: string | URL, init: RequestInit = {}): Promise<Response> {
  let url = assertSafeUrl(input, { allowHttp: true });
  const safeInit: RequestInit = { ...init, redirect: "manual" };
  for (let hop = 0; hop < 5; hop++) {
    const response = await fetch(url, safeInit);
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      await response.body?.cancel().catch(() => undefined);
      if (!location) throw new Error("下载重定向缺少目标地址");
      url = assertSafeUrl(new URL(location, url), { allowHttp: true });
      continue;
    }
    return response;
  }
  throw new Error("下载重定向次数过多");
}
