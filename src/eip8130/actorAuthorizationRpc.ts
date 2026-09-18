import { BaseError } from '../errors/base.js'
import type {
  WalletRequestActorParameters,
  WalletRequestActorReturnType,
} from '../types/eip1193.js'
import { numberToHex } from '../utils/encoding/toHex.js'
import type {
  RequestActorParameters,
  RequestActorReturnType,
} from './actorAuthorization.js'
import {
  assertActorRequest,
  assertChainId,
  assertFields,
  assertPolicyConfig,
  parseUint,
} from './utils/actorAuthorization.js'

/** Serializes an actor request to JSON-safe wallet_requestActor parameters. */
export function serializeRequestActorParameters(
  parameters: RequestActorParameters & { chainId: number },
): WalletRequestActorParameters {
  assertChainId(parameters.chainId)
  assertActorRequest(parameters)
  assertPolicyConfig(parameters.policy)
  const { account, actor, scope, expiry, chainId, policy } = parameters
  return {
    ...(account !== undefined ? { account } : {}),
    chainId: numberToHex(chainId),
    actor: { actorId: actor.actorId, authenticator: actor.authenticator },
    scope: numberToHex(scope),
    expiry: numberToHex(expiry),
    policy: {
      version: policy.version,
      data: {
        tokenLimits: policy.data.tokenLimits?.map(
          ({ token, limit, period }) => ({
            token,
            limit: numberToHex(limit),
            ...(period !== undefined ? { period: numberToHex(period) } : {}),
          }),
        ),
        callScopes: policy.data.callScopes?.map(
          ({ target, selectorRules }) => ({
            target,
            selectorRules: selectorRules?.map(({ selector, recipients }) => ({
              selector,
              recipients: recipients?.slice(),
            })),
          }),
        ),
      },
    },
  }
}

/**
 * Parses untrusted JSON into request fields for review. This is not approval:
 * wallets must explicitly select trusted fulfillment options after user consent.
 */
export function parseRequestActorParameters(
  wire: WalletRequestActorParameters,
): RequestActorParameters & { chainId: number } {
  assertFields(wire, [
    'account',
    'chainId',
    'actor',
    'scope',
    'expiry',
    'policy',
  ])
  assertFields(wire.actor, ['actorId', 'authenticator'])
  assertFields(wire.policy, ['version', 'data'])
  assertFields(wire.policy.data, ['tokenLimits', 'callScopes'])
  const data = wire.policy.data
  if (data.tokenLimits !== undefined && !Array.isArray(data.tokenLimits))
    throw new BaseError('Invalid tokenLimits.')
  const parameters = {
    account: wire.account,
    chainId: Number(parseUint(wire.chainId, 53)),
    actor: {
      actorId: wire.actor.actorId,
      authenticator: wire.actor.authenticator,
    },
    scope: Number(parseUint(wire.scope, 16)),
    expiry: parseUint(wire.expiry, 40),
    policy: {
      version: wire.policy.version,
      data: {
        tokenLimits: data.tokenLimits?.map((limit) => {
          assertFields(limit, ['token', 'limit', 'period'])
          return {
            token: limit.token,
            limit: parseUint(limit.limit, 160),
            ...(limit.period !== undefined
              ? { period: parseUint(limit.period, 40) }
              : {}),
          }
        }),
        callScopes: data.callScopes,
      },
    },
  }
  // Also validates nested call scopes, scalar bounds, identities, and version.
  serializeRequestActorParameters(parameters)
  return parameters
}

/** Serializes a fulfillment for JSON-RPC. The app still validates it against its request. */
export function serializeRequestActorResult(
  result: RequestActorReturnType,
): WalletRequestActorReturnType {
  const signed = result.signedAccountChanges
  if (
    signed.type !== 'config' ||
    signed.channel !== 'local' ||
    signed.sequence < 0n ||
    signed.sequence >= 1n << 64n ||
    (signed.sequence & 0xffff_ffffn) !== 0xffff_ffffn
  )
    throw new BaseError('Expected a local unsequenced config batch.')
  return {
    account: result.account,
    chainId: numberToHex(result.chainId),
    permissionsContext: result.permissionsContext,
    signedAccountChanges: {
      type: 'config',
      channel: 'local',
      sequence: numberToHex(signed.sequence),
      signature: signed.signature,
      changes: signed.changes.map((change) => {
        if (change.changeType !== 0)
          throw new BaseError('Expected only authorizeActor changes.')
        return {
          changeType: '0x0',
          actorId: change.actorId,
          authenticator: change.authenticator,
          scope: numberToHex(change.scope ?? 0),
          expiry: numberToHex(change.expiry ?? 0n),
          policyData: change.policyData ?? '0x',
        }
      }),
    },
  }
}
