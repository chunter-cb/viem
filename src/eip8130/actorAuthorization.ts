import type { Address } from 'abitype'
import { getChainId } from '../actions/public/getChainId.js'
import type { Client } from '../clients/createClient.js'
import type { Transport } from '../clients/transports/createTransport.js'
import { zeroAddress } from '../constants/address.js'
import { BaseError } from '../errors/base.js'
import type { Account } from '../types/account.js'
import type { Chain } from '../types/chain.js'
import type { Hex } from '../types/misc.js'
import { decodeAbiParameters } from '../utils/abi/decodeAbiParameters.js'
import { encodeAbiParameters } from '../utils/abi/encodeAbiParameters.js'
import { isAddressEqual } from '../utils/address/isAddressEqual.js'
import { stringToHex } from '../utils/encoding/toHex.js'
import { keccak256 } from '../utils/hash/keccak256.js'
import { getActorConfig } from './actions/getActorConfig.js'
import {
  getConfigSequence,
  unsequencedLocalSequence,
} from './actions/getConfigSequence.js'
import { actorScope, ecrecoverAuthenticator } from './constants.js'
import { authorizeActor, key } from './keys.js'
import {
  commitmentOf,
  defineSessionPolicy,
  encodeSessionPolicyConfig,
  type SessionPolicy,
  type SessionPolicyConfig,
} from './policies.js'
import type {
  AaAccountChangeConfig,
  AaAuthorizeActor,
} from './types/transaction.js'
import {
  assertActorRequest,
  assertAddress,
  assertChainId,
  assertNoActorCollision,
  assertPolicyConfig,
} from './utils/actorAuthorization.js'
import {
  type SignAccountChangesErrorType,
  signAccountChanges,
} from './utils/signActorChanges.js'
import type { Signer } from './utils/signTransaction.js'

export const actorAuthorizationPolicyVersions = ['session-policy-v1'] as const
export type ActorAuthorizationPolicyVersion =
  (typeof actorAuthorizationPolicyVersions)[number]
export type ActorAuthorizationPolicy = {
  version: ActorAuthorizationPolicyVersion
  data: SessionPolicyConfig
}

/** An identity only, never an actor's existing scope or policyData. */
export type ActorAuthorizationIdentity = {
  actorId: Hex
  authenticator: Address
}

export type RequestActorParameters = {
  /** Omit to let the wallet resolve the active account. */
  account?: Address | undefined
  /** Exact signing chain. Defaults to client.chain.id; sent explicitly over RPC. */
  chainId?: number | undefined
  actor: ActorAuthorizationIdentity
  /** POLICY, optionally NONCE and SELF_PAYER. */
  scope: number
  /** Finite uint40 expiry in unix seconds. */
  expiry: number | bigint
  policy: ActorAuthorizationPolicy
}

export type RequestActorReturnType = {
  account: Address
  chainId: number
  signedAccountChanges: AaAccountChangeConfig
  /** Self-describing context, not proof of cryptographic authority. */
  permissionsContext: Hex
}

/** Version tag distinct from the unchanged legacy ERC-7715 context format. */
export const actorAuthorizationContextMagic = keccak256(
  stringToHex('eip8130.actorAuthorizationContext.v1'),
)
const contextParameters = [
  { type: 'bytes32' }, // magic
  { type: 'address' }, // account
  { type: 'bytes32' }, // actorId
  { type: 'address' }, // authenticator
  { type: 'uint16' }, // scope
  { type: 'uint48' }, // expiry
  { type: 'address' }, // manager
  { type: 'address' }, // policy
  { type: 'bytes' }, // policyConfig
  { type: 'uint40' }, // validAfter
  { type: 'uint256' }, // salt
] as const

export type ToActorAuthorizationContextParameters = {
  account: Address
  actor: ActorAuthorizationIdentity
  scope: number
  /** Must equal session.binding.validUntil. */
  expiry: bigint
  session: SessionPolicy
}
export type ParseActorAuthorizationContextReturnType =
  ToActorAuthorizationContextParameters

/** Encodes a v1 context without changing the supplied session commitment. */
export function toActorAuthorizationContext(
  parameters: ToActorAuthorizationContextParameters,
): Hex {
  const { account, actor, scope, expiry, session } = parameters
  const { binding } = session
  assertActorRequest({ account, actor, scope, expiry })
  assertAddress(session.manager)
  assertAddress(session.policy)
  assertNoActorCollision(actor, account, session.manager)
  if (session.actorPolicy.type !== 1)
    throw new BaseError('Unsupported context policy type; v1 requires type 1.')
  if (
    !isAddressEqual(account, binding.account) ||
    expiry !== binding.validUntil ||
    !isAddressEqual(session.policy, binding.policy) ||
    !isAddressEqual(session.manager, session.actorPolicy.manager) ||
    session.commitment.toLowerCase() !== commitmentOf(binding).toLowerCase() ||
    session.actorPolicy.commitment.toLowerCase() !==
      session.commitment.toLowerCase()
  )
    throw new BaseError(
      'Context account, expiry, or policy does not match session binding.',
    )
  return encodeAbiParameters(contextParameters, [
    actorAuthorizationContextMagic,
    account,
    actor.actorId,
    actor.authenticator,
    scope,
    Number(expiry),
    session.manager,
    session.policy,
    binding.policyConfig,
    Number(binding.validAfter),
    binding.salt,
  ])
}

/** Parses a v1 context. Does not authenticate a signed account-change batch. */
export function parseActorAuthorizationContext(
  context: Hex,
): ParseActorAuthorizationContextReturnType {
  let decoded: ReturnType<typeof decodeContext>
  try {
    decoded = decodeContext(context)
  } catch (cause) {
    throw new BaseError(
      'Invalid actor authorization context (version tag or encoding).',
      { cause: cause as Error },
    )
  }
  const [
    magic,
    account,
    actorId,
    authenticator,
    scope,
    expiry,
    manager,
    policy,
    policyConfig,
    validAfter,
    salt,
  ] = decoded
  if (magic !== actorAuthorizationContextMagic)
    throw new BaseError('Invalid actor authorization context version tag.')
  const session = defineSessionPolicy({
    account,
    manager,
    policy,
    policyConfig,
    validAfter: BigInt(validAfter),
    validUntil: BigInt(expiry),
    salt,
  })
  const result = {
    account,
    actor: { actorId, authenticator },
    scope,
    expiry: BigInt(expiry),
    session,
  }
  if (
    toActorAuthorizationContext(result).toLowerCase() !== context.toLowerCase()
  )
    throw new BaseError('Noncanonical actor authorization context.')
  return result
}
function decodeContext(context: Hex) {
  return decodeAbiParameters(contextParameters, context)
}

export type FulfillRequestActorParameters = {
  account: Address
  chainId?: number | undefined
  signer: Signer
  /** Wallet-approved identity; the wallet must trust its authenticator. */
  actor: ActorAuthorizationIdentity
  scope: number
  /** Preserve the exact approved request expiry, do not recompute it. */
  expiry: number | bigint
  policyVersion: ActorAuthorizationPolicyVersion
  policyConfig: SessionPolicyConfig
  /** Wallet-trusted contracts, never selected by an untrusted request. */
  manager: Address
  policy: Address
  /** Explicit approval to register/reactivate a no-live manager as an unbounded OPERATOR.
   * This sibling remains replayable even after the session expires, until an epoch bump. */
  approveManagerRegistration?: boolean | undefined
  /** Separate gas-spend approval, required for SELF_PAYER. */
  allowSelfPayer?: boolean | undefined
  /** Defaults to 0n, preserving budget identity across reuse of the same binding. */
  salt?: bigint | undefined
}
export type FulfillRequestActorReturnType = RequestActorReturnType & {
  actor: ActorAuthorizationIdentity
  change: AaAuthorizeActor
  managerChange?: AaAuthorizeActor | undefined
  changes: readonly AaAuthorizeActor[]
  session: SessionPolicy
}
export type FulfillRequestActorErrorType =
  | SignAccountChangesErrorType
  | BaseError

/**
 * Signs an approved scoped grant without broadcasting. Restate approved request
 * fields explicitly; never spread an untrusted RPC object into these options.
 * Reads transport chain, live manager, requested actor, and local epoch before signing.
 */
export async function fulfillRequestActor<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: FulfillRequestActorParameters,
): Promise<FulfillRequestActorReturnType> {
  const {
    account,
    signer,
    actor,
    scope,
    expiry,
    policyVersion,
    policyConfig,
    manager,
    policy,
    approveManagerRegistration = false,
    allowSelfPayer = false,
    salt,
  } = parameters
  const chainId = parameters.chainId ?? client.chain?.id
  assertChainId(chainId)
  if (client.chain && chainId !== client.chain.id)
    throw new BaseError('Requested chainId differs from client chain.')
  assertActorRequest({ account, actor, scope, expiry })
  assertAddress(account)
  assertAddress(manager)
  assertAddress(policy)
  assertPolicyConfig({ version: policyVersion, data: policyConfig })
  assertNoActorCollision(actor, account, manager)
  if (scope & actorScope.selfPayer && allowSelfPayer !== true)
    throw new BaseError(
      'SELF_PAYER requires allowSelfPayer: true (gas is not capped by policy).',
    )
  const expiryBig = BigInt(expiry)
  if (expiryBig <= BigInt(Math.floor(Date.now() / 1000)))
    throw new BaseError('Expiry must be in the future.')

  // Always verify the transport, even when configured chain metadata is present.
  if ((await getChainId(client)) !== chainId)
    throw new BaseError('RPC chainId differs from requested signing chain.')
  const managerActor = key.k1(manager)
  const managerConfig = await getActorConfig(client, {
    account,
    actorId: managerActor.actorId,
  })
  let managerChange: AaAuthorizeActor | undefined
  // The public getter collapses absent/revoked/disabled/expired to zero.
  if (isAddressEqual(managerConfig.authenticator, zeroAddress)) {
    if (approveManagerRegistration !== true)
      throw new BaseError(
        'No live manager; approveManagerRegistration is required to register/reactivate it.',
      )
    managerChange = authorizeActor(managerActor, { scope: actorScope.operator })
  } else {
    if (!isAddressEqual(managerConfig.authenticator, ecrecoverAuthenticator))
      throw new BaseError('Live manager has an unexpected authenticator.')
    if (
      managerConfig.scope !== 0 &&
      !(managerConfig.scope & actorScope.operator)
    )
      throw new BaseError(
        'Live manager lacks operational scope; refusing to upgrade it.',
      )
  }
  const existing = await getActorConfig(client, {
    account,
    actorId: actor.actorId,
  })
  if (
    !isAddressEqual(existing.authenticator, zeroAddress) &&
    (existing.scope === 0 ||
      !isAddressEqual(existing.authenticator, actor.authenticator))
  )
    throw new BaseError(
      'Refusing to replace a live admin or different-authenticator actor.',
    )

  const session = defineSessionPolicy({
    account,
    manager,
    policy,
    policyConfig: encodeSessionPolicyConfig(policyConfig),
    validUntil: expiryBig,
    salt,
  })
  const change = authorizeActor(actor, {
    scope,
    policy: session.actorPolicy,
    expiry: expiryBig,
  })
  const changes = managerChange ? [managerChange, change] : [change]
  const { localEpoch } = await getConfigSequence(client, { account })
  const signedAccountChanges = await signAccountChanges({
    signer,
    account,
    channel: 'local',
    chainId,
    sequence: unsequencedLocalSequence(localEpoch),
    changes,
  })
  const permissionsContext = toActorAuthorizationContext({
    account,
    actor,
    scope,
    expiry: expiryBig,
    session,
  })
  return {
    account,
    chainId,
    actor,
    change,
    managerChange,
    changes,
    session,
    signedAccountChanges,
    permissionsContext,
  }
}
