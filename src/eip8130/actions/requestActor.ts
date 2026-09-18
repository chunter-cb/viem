import type { Client } from '../../clients/createClient.js'
import type { Transport } from '../../clients/transports/createTransport.js'
import { BaseError } from '../../errors/base.js'
import type { Chain } from '../../types/chain.js'
import type { WalletRequestActorChange } from '../../types/eip1193.js'
import { isAddressEqual } from '../../utils/address/isAddressEqual.js'
import { size } from '../../utils/data/size.js'
import { slice } from '../../utils/data/slice.js'
import {
  parseActorAuthorizationContext,
  type RequestActorParameters,
  type RequestActorReturnType,
} from '../actorAuthorization.js'
import {
  parseRequestActorParameters,
  serializeRequestActorParameters,
} from '../actorAuthorizationRpc.js'
import { actorScope, ecrecoverAuthenticator } from '../constants.js'
import { encodePolicyData, key } from '../keys.js'
import { encodeSessionPolicyConfig } from '../policies.js'
import type { AaAuthorizeActor } from '../types/transaction.js'
import {
  assertAddress,
  assertBytes,
  assertChainId,
  assertFields,
  assertNoActorCollision,
  parseUint,
} from '../utils/actorAuthorization.js'

/**
 * Requests a scoped, finite actor grant (experimental wallet_requestActor).
 * Validates the complete batch and exact requested policy, not cryptographic
 * authority. The chain authenticates the raw account-change signature on submission.
 */
export async function requestActor<chain extends Chain | undefined>(
  client: Client<Transport, chain>,
  parameters: RequestActorParameters,
): Promise<RequestActorReturnType> {
  const chainId = parameters.chainId ?? client.chain?.id
  assertChainId(chainId)
  if (client.chain && chainId !== client.chain.id)
    throw new BaseError('Requested chainId differs from client chain.')
  const wire = serializeRequestActorParameters({ ...parameters, chainId })
  const request = parseRequestActorParameters(wire)
  const expectedPolicy = encodeSessionPolicyConfig(request.policy.data)
  const result = await client.request(
    { method: 'wallet_requestActor', params: [wire] },
    { retryCount: 0 },
  )
  assertFields(result, [
    'account',
    'chainId',
    'signedAccountChanges',
    'permissionsContext',
  ])
  assertAddress(result.account)
  if (request.account && !isAddressEqual(result.account, request.account))
    throw new BaseError('Response does not match requested account.')
  if (parseUint(result.chainId, 53) !== BigInt(chainId))
    throw new BaseError('Response is bound to a different chain.')
  const signed = result.signedAccountChanges
  assertFields(signed, ['type', 'channel', 'sequence', 'changes', 'signature'])
  const sequence = parseUint(signed.sequence, 64)
  if (
    signed.type !== 'config' ||
    signed.channel !== 'local' ||
    (sequence & 0xffff_ffffn) !== 0xffff_ffffn
  )
    throw new BaseError('Expected a local unsequenced config batch.')
  assertBytes(signed.signature)
  if (size(signed.signature) < 20)
    throw new BaseError('Malformed account-change signature.')
  const authenticator = slice(signed.signature, 0, 20)
  assertAddress(authenticator)
  if (
    isAddressEqual(authenticator, ecrecoverAuthenticator) &&
    size(signed.signature) !== 85
  )
    throw new BaseError('Malformed k1 account-change signature.')
  if (
    !Array.isArray(signed.changes) ||
    signed.changes.length < 1 ||
    signed.changes.length > 2
  )
    throw new BaseError(
      'Expected one actor grant and optional preceding manager registration.',
    )
  const changes = signed.changes.map(parseGrant)
  const change = changes[changes.length - 1]!
  if (
    change.actorId.toLowerCase() !== request.actor.actorId.toLowerCase() ||
    !isAddressEqual(change.authenticator, request.actor.authenticator)
  )
    throw new BaseError(
      'Response does not include a signed `authorizeActor` change for the requested actor.',
    )
  if (change.scope !== request.scope)
    throw new BaseError('Response does not match the requested scope.')
  if (change.expiry !== BigInt(request.expiry))
    throw new BaseError('Response does not match the requested expiry.')

  const context = parseActorAuthorizationContext(result.permissionsContext)
  if (!isAddressEqual(context.account, result.account))
    throw new BaseError('permissionsContext account mismatch.')
  if (
    context.actor.actorId.toLowerCase() !== change.actorId.toLowerCase() ||
    !isAddressEqual(context.actor.authenticator, change.authenticator) ||
    context.scope !== change.scope ||
    context.expiry !== change.expiry
  )
    throw new BaseError('permissionsContext actor/scope/expiry mismatch.')
  if (
    context.session.binding.validAfter !== 0n ||
    context.session.binding.policyConfig.toLowerCase() !==
      expectedPolicy.toLowerCase()
  )
    throw new BaseError(
      'Response policy does not match the requested session-policy-v1 intent.',
    )
  if (
    change.policyData?.toLowerCase() !==
    encodePolicyData(context.session.actorPolicy).toLowerCase()
  )
    throw new BaseError(
      'permissionsContext policy binding does not match signed policyData.',
    )
  assertNoActorCollision(request.actor, result.account, context.session.manager)
  if (changes.length === 2) {
    const prerequisite = changes[0]!
    const manager = key.k1(context.session.manager)
    if (
      prerequisite.actorId.toLowerCase() !== manager.actorId.toLowerCase() ||
      !isAddressEqual(prerequisite.authenticator, manager.authenticator) ||
      prerequisite.scope !== actorScope.operator ||
      prerequisite.expiry !== 0n ||
      prerequisite.policyData !== '0x'
    )
      throw new BaseError('Invalid preceding manager registration.')
  }
  return {
    account: result.account,
    chainId,
    permissionsContext: result.permissionsContext,
    signedAccountChanges: {
      type: 'config',
      channel: 'local',
      sequence,
      changes,
      signature: signed.signature,
    },
  }
}

// Deliberately not an arbitrary account-operation parser.
function parseGrant(wire: WalletRequestActorChange): AaAuthorizeActor {
  assertFields(wire, [
    'changeType',
    'actorId',
    'authenticator',
    'scope',
    'expiry',
    'policyData',
  ])
  if (wire.changeType !== '0x0')
    throw new BaseError('Only authorizeActor operations are allowed.')
  assertBytes(wire.actorId, 32)
  assertAddress(wire.authenticator)
  assertBytes(wire.policyData)
  return {
    changeType: 0,
    actorId: wire.actorId,
    authenticator: wire.authenticator,
    scope: Number(parseUint(wire.scope, 16)),
    expiry: parseUint(wire.expiry, 40),
    policyData: wire.policyData,
  }
}
