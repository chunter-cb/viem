import type { Address } from 'abitype'
import { zeroAddress } from '../../constants/address.js'
import { BaseError } from '../../errors/base.js'
import type { Hex } from '../../types/misc.js'
import { isAddress } from '../../utils/address/isAddress.js'
import { isAddressEqual } from '../../utils/address/isAddressEqual.js'
import { isHex } from '../../utils/data/isHex.js'
import { size } from '../../utils/data/size.js'
import type {
  ActorAuthorizationPolicy,
  RequestActorParameters,
} from '../actorAuthorization.js'
import { actorScope } from '../constants.js'
import { key } from '../keys.js'

/** @internal Strict field checks prevent silently dropping declarative constraints. */
export function assertFields(value: object, fields: readonly string[]) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).some((k) => !fields.includes(k))
  )
    throw new BaseError('Unsupported or malformed actor authorization fields.')
}

/** @internal */
export function assertAddress(value: Address, allowZero = false) {
  if (
    typeof value !== 'string' ||
    !isAddress(value, { strict: false }) ||
    (!allowZero && isAddressEqual(value, zeroAddress))
  )
    throw new BaseError('Invalid or zero actor authorization address.')
}

/** @internal */
export function assertBytes(value: Hex, length?: number) {
  if (
    !isHex(value, { strict: true }) ||
    value.length % 2 !== 0 ||
    (length !== undefined && size(value) !== length)
  )
    throw new BaseError('Malformed actor authorization hex bytes.')
}

/** @internal Hex quantities only, with explicit scalar bounds. */
export function parseUint(value: Hex, bits: number): bigint {
  if (
    typeof value !== 'string' ||
    !/^0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)$/.test(value)
  )
    throw new BaseError('Malformed actor authorization hex quantity.')
  const n = BigInt(value)
  assertUint(n, bits)
  return n
}

/** @internal */
export function assertUint(value: number | bigint, bits: number) {
  if (
    (typeof value !== 'number' && typeof value !== 'bigint') ||
    (typeof value === 'number' && !Number.isSafeInteger(value)) ||
    BigInt(value) < 0n ||
    BigInt(value) >= 1n << BigInt(bits)
  )
    throw new BaseError(`Expected an integer within uint${bits} bounds.`)
}

/** @internal */
export function assertChainId(
  value: number | undefined,
): asserts value is number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0)
    throw new BaseError('A positive safe integer chainId is required.')
}

/** @internal */
export function assertActorRequest({
  account,
  actor,
  scope,
  expiry,
}: Pick<RequestActorParameters, 'account' | 'actor' | 'scope' | 'expiry'>) {
  if (account !== undefined) assertAddress(account)
  assertFields(actor, ['actorId', 'authenticator'])
  assertBytes(actor.actorId, 32)
  if (BigInt(actor.actorId) === 0n)
    throw new BaseError('Zero actor identity is not supported.')
  assertAddress(actor.authenticator)
  assertUint(scope, 16)
  if (scope === 0) throw new BaseError('Refusing admin scope.')
  if (scope & actorScope.operator)
    throw new BaseError('Refusing operator scope.')
  if (!(scope & actorScope.policy))
    throw new BaseError('Scope requires actorScope.policy.')
  if (scope & ~(actorScope.policy | actorScope.nonce | actorScope.selfPayer))
    throw new BaseError('Refusing unsupported scope bits.')
  assertUint(expiry, 40)
  if (BigInt(expiry) === 0n)
    throw new BaseError('Expiry must be finite and nonzero.')
}

/** @internal */
export function assertNoActorCollision(
  actor: { actorId: Hex },
  account: Address,
  manager: Address,
) {
  const id = actor.actorId.toLowerCase()
  if (
    id === key.k1(manager).actorId.toLowerCase() ||
    id === key.k1(account).actorId.toLowerCase()
  )
    throw new BaseError(
      'Requested actor collides with manager or self actor identity.',
    )
}

/** @internal Validate v1's complete declarative schema before encoding it. */
export function assertPolicyConfig(policy: ActorAuthorizationPolicy) {
  assertFields(policy, ['version', 'data'])
  if (policy.version !== 'session-policy-v1')
    throw new BaseError('Unsupported policy version.')
  const config = policy.data
  assertFields(config, ['tokenLimits', 'callScopes'])
  if (config.tokenLimits !== undefined && !Array.isArray(config.tokenLimits))
    throw new BaseError('Invalid tokenLimits.')
  if (config.callScopes !== undefined && !Array.isArray(config.callScopes))
    throw new BaseError('Invalid callScopes.')
  for (const limit of config.tokenLimits ?? []) {
    assertFields(limit, ['token', 'limit', 'period'])
    assertAddress(limit.token, true)
    if (
      typeof limit.limit !== 'bigint' ||
      (limit.period !== undefined && typeof limit.period !== 'bigint')
    )
      throw new BaseError('Policy limit/period must be bigint.')
    assertUint(limit.limit, 160)
    if (limit.period !== undefined) assertUint(limit.period, 40)
  }
  for (const scope of config.callScopes ?? []) {
    assertFields(scope, ['target', 'selectorRules'])
    assertAddress(scope.target, true)
    if (
      scope.selectorRules !== undefined &&
      !Array.isArray(scope.selectorRules)
    )
      throw new BaseError('Invalid selectorRules.')
    for (const rule of scope.selectorRules ?? []) {
      assertFields(rule, ['selector', 'recipients'])
      assertBytes(rule.selector, 4)
      if (rule.recipients !== undefined && !Array.isArray(rule.recipients))
        throw new BaseError('Invalid recipients.')
      for (const recipient of rule.recipients ?? [])
        assertAddress(recipient, true)
    }
  }
}
