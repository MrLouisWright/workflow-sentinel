export function cacheKeyFields(withJs: any): string[][];
/** Returns finding messages for cache poisoning on a cache/restore step. */
export function checkCachePoisoning(uses: any, withJs: any, taintedEnv: any, untrustedRes: any): {
    field: string;
    value: string;
}[];
/** artipacked: credentials or PR output packaged into artifacts. */
export function checkArtipacked(ctx: any): {
    kind: string;
    message: string;
}[];
export const CACHE_ACTIONS: RegExp;
export const UPLOAD_ARTIFACT: RegExp;
export const DOWNLOAD_ARTIFACT: RegExp;
export const CHECKOUT: RegExp;
