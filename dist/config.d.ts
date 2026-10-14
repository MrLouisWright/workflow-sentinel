export function loadConfig(dir: string, explicit: any): {
    failOn: string;
    trustedOwners: any[];
    rules: {};
    allow: any[];
    ignore: any[];
};
/**
 * allow: [{ rule?, file?, target?, reason?, expires? }] or "rule" / "rule:target-glob"
 * target matches the action ("actions/checkout"), image, or nothing.
 */
export function isAllowed(allow: any, f: any, now?: number): boolean;
export function ownerTrusted(trusted: any, f: any): any;
export const CONFIG_FILES: string[];
export namespace DEFAULTS {
    let failOn: string;
    let trustedOwners: any[];
    let rules: {};
    let allow: any[];
    let ignore: any[];
}
