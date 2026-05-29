// Self-contained, minimal replacement for the slice of `drand-client` that
// tlock-js actually uses. Faithfully ports the semantics of drand-client
// v1.2.x (lib/{index,util,beacon-verification,http-caching-chain,http-chain-client}.ts)
// while depending only on @noble/curves + @noble/hashes + buffer and the
// runtime's global `fetch`. This drops drand-client and its transitive
// @babel/traverse / isomorphic-fetch dependencies from the supply chain.
//
// Beacon signature verification is preserved (and is what protects a caller
// against a malicious/incorrect drand endpoint), so a fetched round signature
// is cryptographically checked against the chain's public key before use.

import {bls12_381 as bls} from "@noble/curves/bls12-381"
import {sha256} from "@noble/hashes/sha256"
import {Buffer} from "buffer"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// `ChainInfo` is returned by a node's `/info` endpoint.
export type ChainInfo = {
    public_key: string    // hex encoded BLS12-381 public key
    period: number        // how often the network emits randomness (in seconds)
    genesis_time: number  // the time of round 0 of the network (epoch seconds)
    hash: string          // the hash identifying this specific chain of beacons
    groupHash: string     // hash of the group file describing the participating nodes
    schemeID: string      // the version/format of cryptography
    metadata: {
        beaconID: string
    }
}

export type G2ChainedBeacon = {
    round: number
    randomness: string
    signature: string
    previous_signature: string
}

export type G2UnchainedBeacon = {
    round: number
    randomness: string
    signature: string
    _phantomg2?: never
}

export type G1UnchainedBeacon = {
    round: number
    randomness: string
    signature: string
    _phantomg1?: never
}

export type G1RFC9380Beacon = {
    round: number
    randomness: string
    signature: string
    _phantomg19380?: never
}

export type RandomnessBeacon = G2ChainedBeacon | G2UnchainedBeacon | G1UnchainedBeacon | G1RFC9380Beacon

export type ChainVerificationParams = {
    chainHash: string
    publicKey: string
}

export type ChainOptions = {
    // skip beacon signature verification (not recommended)
    disableBeaconVerification: boolean
    // append a query param to stop providers returning a cached version
    noCache: boolean
    // if set, the chain info must match these params or an error is thrown
    chainVerificationParams?: ChainVerificationParams
}

export const defaultChainOptions: ChainOptions = {
    disableBeaconVerification: false,
    noCache: false,
}

export type HttpOptions = {
    userAgent?: string
    headers?: Record<string, string>
}

export const defaultHttpOptions: HttpOptions = {
    userAgent: "tlock-js",
}

// functionality for a given chain hosted by a node
export interface Chain {
    baseUrl: string

    info(): Promise<ChainInfo>
}

// functionality for fetching individual beacons for a given `Chain`.
// Implement this yourself to support protocols other than HTTP.
export interface ChainClient {
    options: ChainOptions

    latest(): Promise<RandomnessBeacon>

    get(roundNumber: number): Promise<RandomnessBeacon>

    chain(): Chain
}

// ---------------------------------------------------------------------------
// Round timing (pure functions)
// ---------------------------------------------------------------------------

export function roundAt(time: number, chain: ChainInfo): number {
    if (!Number.isFinite(time)) {
        throw new Error("Cannot use Infinity or NaN as a beacon time")
    }
    if (time < chain.genesis_time * 1000) {
        throw Error("Cannot request a round before the genesis time")
    }
    return Math.floor((time - (chain.genesis_time * 1000)) / (chain.period * 1000)) + 1
}

export function roundTime(chain: ChainInfo, round: number): number {
    if (!Number.isFinite(round)) {
        throw new Error("Cannot use Infinity or NaN as a round number")
    }
    round = round < 0 ? 0 : round
    return (chain.genesis_time + (round - 1) * chain.period) * 1000
}

// ---------------------------------------------------------------------------
// HTTP transport (native fetch)
// ---------------------------------------------------------------------------

async function jsonOrError(url: string, options: HttpOptions = defaultHttpOptions): Promise<unknown> {
    const headers = {...options.headers}
    if (options.userAgent) {
        headers["User-Agent"] = options.userAgent
    }

    const response = await fetch(url, {headers})
    if (!response.ok) {
        throw Error(`Error response fetching ${url} - got ${response.status}`)
    }
    return await response.json()
}

export class HttpChain implements Chain {
    constructor(
        public baseUrl: string,
        private options: ChainOptions = defaultChainOptions,
        private httpOptions: HttpOptions = {}) {
    }

    async info(): Promise<ChainInfo> {
        const chainInfo = await jsonOrError(`${this.baseUrl}/info`, this.httpOptions) as ChainInfo
        if (!!this.options.chainVerificationParams && !isValidInfo(chainInfo, this.options.chainVerificationParams)) {
            throw Error(`The chain info retrieved from ${this.baseUrl} did not match the verification params!`)
        }
        return chainInfo
    }
}

function isValidInfo(chainInfo: ChainInfo, validParams: ChainVerificationParams): boolean {
    return chainInfo.hash === validParams.chainHash && chainInfo.public_key === validParams.publicKey
}

export class HttpCachingChain implements Chain {
    private chain: Chain
    private cachedInfo?: ChainInfo

    constructor(public baseUrl: string, private options: ChainOptions = defaultChainOptions) {
        this.chain = new HttpChain(baseUrl, options)
    }

    async info(): Promise<ChainInfo> {
        if (!this.cachedInfo) {
            this.cachedInfo = await this.chain.info()
        }
        return this.cachedInfo
    }
}

export class HttpChainClient implements ChainClient {
    constructor(
        private someChain: Chain,
        public options: ChainOptions = defaultChainOptions,
        public httpOptions: HttpOptions = defaultHttpOptions) {
    }

    async get(roundNumber: number): Promise<RandomnessBeacon> {
        const url = withCachingParams(`${this.someChain.baseUrl}/public/${roundNumber}`, this.options)
        return await jsonOrError(url, this.httpOptions) as RandomnessBeacon
    }

    async latest(): Promise<RandomnessBeacon> {
        const url = withCachingParams(`${this.someChain.baseUrl}/public/latest`, this.options)
        return await jsonOrError(url, this.httpOptions) as RandomnessBeacon
    }

    chain(): Chain {
        return this.someChain
    }
}

function withCachingParams(url: string, config: ChainOptions): string {
    if (config.noCache) {
        return `${url}?${Date.now()}`
    }
    return url
}

// ---------------------------------------------------------------------------
// Beacon fetching + verification
// ---------------------------------------------------------------------------

export async function fetchBeacon(client: ChainClient, roundNumber?: number): Promise<RandomnessBeacon> {
    if (!roundNumber) {
        roundNumber = roundAt(Date.now(), await client.chain().info())
    }
    if (roundNumber < 1) {
        throw Error("Cannot request lower than round number 1")
    }
    const beacon = await client.get(roundNumber)
    return validatedBeacon(client, beacon, roundNumber)
}

async function validatedBeacon(client: ChainClient, beacon: RandomnessBeacon, expectedRound: number): Promise<RandomnessBeacon> {
    if (client.options.disableBeaconVerification) {
        return beacon
    }
    const info = await client.chain().info()
    if (!await verifyBeacon(info, beacon, expectedRound)) {
        throw Error("The beacon retrieved was not valid!")
    }
    return beacon
}

// ---- type guards (scheme detection) ----

export function isChainedBeacon(value: RandomnessBeacon, info: ChainInfo): value is G2ChainedBeacon {
    return info.schemeID === "pedersen-bls-chained" &&
        !!(value as G2ChainedBeacon).previous_signature &&
        !!value.randomness &&
        !!value.signature &&
        value.round > 0
}

export function isUnchainedBeacon(value: RandomnessBeacon, info: ChainInfo): value is G2UnchainedBeacon {
    return info.schemeID === "pedersen-bls-unchained" &&
        !!value.randomness &&
        !!value.signature &&
        (value as G2ChainedBeacon).previous_signature === undefined &&
        value.round > 0
}

export function isG1G2SwappedBeacon(value: RandomnessBeacon, info: ChainInfo): value is G1UnchainedBeacon {
    return info.schemeID === "bls-unchained-on-g1" &&
        !!value.randomness &&
        !!value.signature &&
        (value as G2ChainedBeacon).previous_signature === undefined &&
        value.round > 0
}

export function isG1Rfc9380(value: RandomnessBeacon, info: ChainInfo): value is G1RFC9380Beacon {
    return info.schemeID === "bls-unchained-g1-rfc9380" &&
        !!value.randomness &&
        !!value.signature &&
        (value as G2ChainedBeacon).previous_signature === undefined &&
        value.round > 0
}

export async function verifyBeacon(chainInfo: ChainInfo, beacon: RandomnessBeacon, expectedRound: number): Promise<boolean> {
    const publicKey = chainInfo.public_key

    if (beacon.round !== expectedRound) {
        console.error("round was not the expected round")
        return false
    }

    if (!await randomnessIsValid(beacon)) {
        console.error("randomness did not match the signature")
        return false
    }

    if (isChainedBeacon(beacon, chainInfo)) {
        return bls.verify(beacon.signature, await chainedBeaconMessage(beacon), publicKey)
    }
    if (isUnchainedBeacon(beacon, chainInfo)) {
        return bls.verify(beacon.signature, await unchainedBeaconMessage(beacon), publicKey)
    }
    if (isG1G2SwappedBeacon(beacon, chainInfo)) {
        return verifySigOnG1(beacon.signature, await unchainedBeaconMessage(beacon), publicKey)
    }
    if (isG1Rfc9380(beacon, chainInfo)) {
        return verifySigOnG1(beacon.signature, await unchainedBeaconMessage(beacon), publicKey, "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_")
    }

    console.error(`Beacon type ${chainInfo.schemeID} was not supported or the beacon was not of the purported type`)
    return false
}

// @noble/curves had not implemented public keys on G2 at the time, so beacons
// with signatures on G1 (fastnet / quicknet) are verified manually via the
// pairing equality e(H(m), -pk) * e(sig, G2) == 1.
type PointG1 = typeof bls.G1.ProjectivePoint.ZERO
type PointG2 = typeof bls.G2.ProjectivePoint.ZERO
type G1Hex = Uint8Array | string | PointG1
type G2Hex = Uint8Array | string | PointG2

function normP1(point: G1Hex): PointG1 {
    return point instanceof bls.G1.ProjectivePoint ? point : bls.G1.ProjectivePoint.fromHex(point)
}

function normP2(point: G2Hex): PointG2 {
    return point instanceof bls.G2.ProjectivePoint ? point : bls.G2.ProjectivePoint.fromHex(point)
}

function normP1Hash(point: G1Hex, domainSeparationTag: string): PointG1 {
    return point instanceof bls.G1.ProjectivePoint
        ? point
        : bls.G1.hashToCurve(point as Uint8Array, {DST: domainSeparationTag}) as PointG1
}

export async function verifySigOnG1(
    signature: G1Hex,
    message: G1Hex,
    publicKey: G2Hex,
    // default DST is the (invalid) one used for 'bls-unchained-on-g1' for backwards compat
    domainSeparationTag = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
): Promise<boolean> {
    const P = normP2(publicKey)
    const Hm = normP1Hash(message, domainSeparationTag)
    const G = bls.G2.ProjectivePoint.BASE
    const S = normP1(signature)
    const ePHm = bls.pairing(Hm, P.negate(), true)
    const eGS = bls.pairing(S, G, true)
    const exp = bls.fields.Fp12.mul(eGS, ePHm)
    return bls.fields.Fp12.eql(exp, bls.fields.Fp12.ONE)
}

async function chainedBeaconMessage(beacon: G2ChainedBeacon): Promise<Uint8Array> {
    const message = Buffer.concat([
        Buffer.from(beacon.previous_signature, "hex"),
        roundBuffer(beacon.round)
    ])
    return sha256(message)
}

async function unchainedBeaconMessage(beacon: RandomnessBeacon): Promise<Uint8Array> {
    return sha256(roundBuffer(beacon.round))
}

function roundBuffer(round: number): Buffer {
    const buffer = Buffer.alloc(8)
    buffer.writeBigUInt64BE(BigInt(round))
    return buffer
}

async function randomnessIsValid(beacon: RandomnessBeacon): Promise<boolean> {
    const expectedRandomness = sha256(Buffer.from(beacon.signature, "hex"))
    return Buffer.from(beacon.randomness, "hex").compare(expectedRandomness) == 0
}
