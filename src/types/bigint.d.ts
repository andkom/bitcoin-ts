/**
 * This placeholder allows us to use BigInt before it's released in TypeScript.
 *
 * Once BigInt support lands, this file can simply be removed.
 */
type BigInt = number;
declare const BigInt: typeof Number;
