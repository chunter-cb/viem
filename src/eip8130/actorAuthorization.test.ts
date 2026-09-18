import type { Abi, Address } from 'abitype'
import { describe, expect, test, vi } from 'vitest'
import { accounts } from '~test/constants.js'
import { privateKeyToAccount } from '../accounts/privateKeyToAccount.js'
import { mainnet } from '../chains/index.js'
import { createClient } from '../clients/createClient.js'
import { custom } from '../clients/transports/custom.js'
import { erc20Abi } from '../constants/abis.js'
import { zeroAddress } from '../constants/address.js'
import { decodeFunctionData } from '../utils/abi/decodeFunctionData.js'
import { encodeFunctionData } from '../utils/abi/encodeFunctionData.js'
import { encodeFunctionResult } from '../utils/abi/encodeFunctionResult.js'
import { slice } from '../utils/data/slice.js'
import { numberToHex } from '../utils/encoding/toHex.js'
import { recoverAddress } from '../utils/signature/recoverAddress.js'
import { keystoreAbi } from './abis.js'
import { toAccount } from './accounts/toAccount.js'
import { requestActor } from './actions/requestActor.js'
import { prepareTransactionRequest } from './actions/sendTransaction.js'
import {
  actorAuthorizationContextMagic,
  actorAuthorizationPolicyVersions,
  fulfillRequestActor,
  parseActorAuthorizationContext,
  toActorAuthorizationContext,
} from './actorAuthorization.js'
import {
  parseRequestActorParameters,
  serializeRequestActorParameters,
  serializeRequestActorResult,
} from './actorAuthorizationRpc.js'
import { actorScope, ecrecoverAuthenticator, nonceKeyMax } from './constants.js'
import { authorizeActor, key } from './keys.js'
import { parsePermissionsContext, toPermissionsContext } from './permissions.js'
import { defineSessionPolicy, encodeSessionPolicyConfig } from './policies.js'
import type { AaChange } from './types/transaction.js'
import { encodeWalletCalls } from './utils/encodeWalletCalls.js'
import { hashAccountChanges } from './utils/hashActorChanges.js'
import { parseTransaction } from './utils/parseTransaction.js'
import { toAccountChangesList } from './utils/serializeTransaction.js'
import { signAccountChanges } from './utils/signActorChanges.js'

const account: Address = '0x0000000000000000000000000000000000000a11'
const usdc: Address = '0x0000000000000000000000000000000000000a22'
const manager: Address = '0x0000000000000000000000000000000000000ba1'
const policy: Address = '0x0000000000000000000000000000000000000c02'
const signer = privateKeyToAccount(accounts[0].privateKey)

const policyConfig = {
  tokenLimits: [{ token: usdc, limit: 100_000_000n }],
} as const

const futureExpiry = BigInt(Math.floor(Date.now() / 1000) + 3600)

/**
 * A client whose `eth_call` answers `getActorConfig` (the manager's actor
 * record) and `getChangeSequences` (the local epoch), and whose `eth_chainId`
 * reports mainnet.
 */
function mockClient(
  options: {
    managerAuthenticator?: string
    managerScope?: number
    managerExpiry?: number
    actorAuthenticator?: string
    actorScope?: number
    rpcChainId?: string
    configuredChain?: boolean
    localEpoch?: number
  } = {},
) {
  const {
    managerAuthenticator = ecrecoverAuthenticator,
    managerScope = actorScope.operator,
    managerExpiry = 0,
    localEpoch = 5,
    actorAuthenticator = zeroAddress,
    actorScope: existingScope = 0,
    rpcChainId = '0x1',
    configuredChain = true,
  } = options
  return createClient({
    chain: configuredChain ? mainnet : undefined,
    transport: custom({
      async request({ method, params }: { method: string; params: any }) {
        if (method === 'eth_chainId') return rpcChainId
        if (method === 'eth_call') {
          const { functionName, args } = decodeFunctionData({
            abi: keystoreAbi as Abi,
            data: params[0].data,
          })
          if (functionName === 'getActorConfig') {
            const isManager = args?.[1] === key.k1(manager).actorId
            const live =
              !isManager ||
              (managerAuthenticator !== zeroAddress &&
                (managerExpiry === 0 ||
                  managerExpiry >= Math.floor(Date.now() / 1000)))
            return encodeFunctionResult({
              abi: keystoreAbi as Abi,
              functionName,
              result: {
                authenticator: live
                  ? isManager
                    ? managerAuthenticator
                    : actorAuthenticator
                  : zeroAddress,
                expiry: live && isManager ? managerExpiry : 0,
                scope: live ? (isManager ? managerScope : existingScope) : 0,
              } as never,
            })
          }
          if (functionName === 'getChangeSequences')
            return encodeFunctionResult({
              abi: keystoreAbi as Abi,
              functionName,
              result: {
                multichain: 0n,
                localEpoch,
                localSequence: 0,
              } as never,
            })
        }
        throw new Error(`unexpected RPC: ${method}`)
      },
    }),
  })
}

/** A client that throws on any request — proves no RPC was made. */
const throwingClient = createClient({
  chain: mainnet,
  transport: custom({
    async request() {
      throw new Error('no RPC expected')
    },
  }),
})

const registeredManagerClient = mockClient()

function baseFulfillParameters() {
  return {
    account,
    signer,
    actor: key.p256({
      x: '0x1000000000000000000000000000000000000000000000000000000000000000',
      y: '0x2000000000000000000000000000000000000000000000000000000000000000',
    }),
    scope: actorScope.policy,
    expiry: futureExpiry,
    policyVersion: 'session-policy-v1' as const,
    policyConfig,
    manager,
    policy,
  }
}

describe('fulfillRequestActor', () => {
  test('happy path: arbitrary (non-k1) actor, exact scope/expiry, current-epoch unsequenced packing, chain binding', async () => {
    const result = await fulfillRequestActor(
      registeredManagerClient,
      baseFulfillParameters(),
    )

    expect(result.account).toBe(account)
    expect(result.chainId).toBe(1)
    expect(result.change.scope).toBe(actorScope.policy)
    expect(result.change.expiry).toBe(futureExpiry)
    expect(result.change.actorId).toBe(baseFulfillParameters().actor.actorId)
    // Non-k1: a p256 authenticator, not the ecrecover sentinel.
    expect(result.change.authenticator).not.toBe(ecrecoverAuthenticator)
    expect(result.managerChange).toBeUndefined()
    expect(result.changes).toEqual([result.change])

    // Bound to the current local epoch, unsequenced (JIT).
    expect(result.signedAccountChanges.channel).toBe('local')
    expect(result.signedAccountChanges.sequence).toBe(
      (5n << 32n) | 0xffff_ffffn,
    )
    expect(result.signedAccountChanges.changes).toEqual([result.change])
    expect(result.signedAccountChanges.signature).toMatch(/^0x[0-9a-f]+$/)
  })

  test('requires an explicit chainId (no default)', async () => {
    const clientWithoutChain = createClient({
      transport: custom({
        async request() {
          throw new Error('no RPC expected')
        },
      }),
    })
    await expect(
      fulfillRequestActor(clientWithoutChain as never, baseFulfillParameters()),
    ).rejects.toThrow(/chainId/)
  })

  test('salt defaults to 0 (not fresh per use) so repeated JIT authorizations keep the same budget identity', async () => {
    const first = await fulfillRequestActor(
      registeredManagerClient,
      baseFulfillParameters(),
    )
    const second = await fulfillRequestActor(registeredManagerClient, {
      ...baseFulfillParameters(),
      // A different ephemeral actor identity for the "next" JIT window...
      actor: key.p256({
        x: '0x3000000000000000000000000000000000000000000000000000000000000000',
        y: '0x4000000000000000000000000000000000000000000000000000000000000000',
      }),
    })
    // ...but the same account/manager/policy/policyConfig/expiry/salt still
    // commit to the identical policy binding (shared spend/budget identity).
    expect(second.session.commitment).toBe(first.session.commitment)
  })

  describe('scope validation (fails closed, before any RPC)', () => {
    test('rejects admin scope (0)', async () => {
      await expect(
        fulfillRequestActor(throwingClient, {
          ...baseFulfillParameters(),
          scope: 0,
        }),
      ).rejects.toThrow(/admin/)
    })

    test('rejects OPERATOR', async () => {
      await expect(
        fulfillRequestActor(throwingClient, {
          ...baseFulfillParameters(),
          scope: actorScope.policy | actorScope.operator,
        }),
      ).rejects.toThrow(/operator/i)
    })

    test('rejects scope missing the POLICY bit', async () => {
      await expect(
        fulfillRequestActor(throwingClient, {
          ...baseFulfillParameters(),
          scope: actorScope.nonce,
        }),
      ).rejects.toThrow(/actorScope\.policy/)
    })

    test('rejects unsupported scope bits (e.g. sponsorPayer)', async () => {
      await expect(
        fulfillRequestActor(throwingClient, {
          ...baseFulfillParameters(),
          scope: actorScope.policy | actorScope.sponsorPayer,
        }),
      ).rejects.toThrow(/unsupported scope bits/)
    })

    test('rejects selfPayer without explicit allowSelfPayer', async () => {
      await expect(
        fulfillRequestActor(throwingClient, {
          ...baseFulfillParameters(),
          scope: actorScope.policy | actorScope.selfPayer,
        }),
      ).rejects.toThrow(/allowSelfPayer/)
    })

    test('accepts selfPayer with explicit allowSelfPayer', async () => {
      const result = await fulfillRequestActor(registeredManagerClient, {
        ...baseFulfillParameters(),
        scope: actorScope.policy | actorScope.selfPayer,
        allowSelfPayer: true,
      })
      expect(result.change.scope).toBe(actorScope.policy | actorScope.selfPayer)
    })
  })

  describe('expiry validation (fails closed, before any RPC)', () => {
    test('rejects zero expiry', async () => {
      await expect(
        fulfillRequestActor(throwingClient, {
          ...baseFulfillParameters(),
          expiry: 0,
        }),
      ).rejects.toThrow(/finite/)
    })

    test('rejects a past expiry', async () => {
      await expect(
        fulfillRequestActor(throwingClient, {
          ...baseFulfillParameters(),
          expiry: 1,
        }),
      ).rejects.toThrow(/future/)
    })

    test('rejects an expiry beyond the policy binding uint40 bound', async () => {
      await expect(
        fulfillRequestActor(throwingClient, {
          ...baseFulfillParameters(),
          expiry: 2n ** 40n,
        }),
      ).rejects.toThrow(/uint40/)
    })

    test('accepts the uint40 boundary itself', async () => {
      const result = await fulfillRequestActor(registeredManagerClient, {
        ...baseFulfillParameters(),
        expiry: 2n ** 40n - 1n,
      })
      expect(result.change.expiry).toBe(2n ** 40n - 1n)
    })
  })

  test('rejects an unsupported policy version (exact-or-error), before any RPC', async () => {
    await expect(
      fulfillRequestActor(throwingClient, {
        ...baseFulfillParameters(),
        policyVersion: 'session-policy-v2' as never,
      }),
    ).rejects.toThrow(/[Uu]nsupported policy version/)
    // Sanity: the fixture used by every other test is actually supported.
    expect(actorAuthorizationPolicyVersions).toContain('session-policy-v1')
  })

  describe('manager liveness / scope (never silently upgraded)', () => {
    test('missing manager + no approval → denies by default', async () => {
      const client = mockClient({ managerAuthenticator: zeroAddress })
      await expect(
        fulfillRequestActor(client, baseFulfillParameters()),
      ).rejects.toThrow(/approveManagerRegistration/)
    })

    test('missing manager + explicit approval → included as a separate OPERATOR change', async () => {
      const client = mockClient({ managerAuthenticator: zeroAddress })
      const result = await fulfillRequestActor(client, {
        ...baseFulfillParameters(),
        approveManagerRegistration: true,
      })
      expect(result.managerChange).toBeDefined()
      expect(result.managerChange?.authenticator).toBe(ecrecoverAuthenticator)
      expect(result.managerChange?.scope).toBe(actorScope.operator)
      expect(result.managerChange?.policyData).toBeUndefined()
      expect(result.changes).toEqual([result.managerChange, result.change])
    })

    test('manager registered with wrong authenticator → throws, never overwritten', async () => {
      const client = mockClient({
        managerAuthenticator: '0x8888888888888888888888888888888888888888',
      })
      await expect(
        fulfillRequestActor(client, baseFulfillParameters()),
      ).rejects.toThrow(/unexpected authenticator/)
    })

    test('manager registered without OPERATOR scope → throws, never silently upgraded', async () => {
      const client = mockClient({ managerScope: actorScope.policy })
      await expect(
        fulfillRequestActor(client, baseFulfillParameters()),
      ).rejects.toThrow(/lacks operational scope/)
    })

    test('expired manager is no-live and needs explicit reactivation consent', async () => {
      const client = mockClient({
        managerScope: actorScope.operator,
        managerExpiry: Math.floor(Date.now() / 1000) - 3600,
      })
      await expect(
        fulfillRequestActor(client, baseFulfillParameters()),
      ).rejects.toThrow(/approveManagerRegistration/)
    })

    test('manager registered, live, sufficient scope → no managerChange', async () => {
      const result = await fulfillRequestActor(
        registeredManagerClient,
        baseFulfillParameters(),
      )
      expect(result.managerChange).toBeUndefined()
    })
  })
})

describe('actorAuthorizationContext', () => {
  test('round-trips account/actor/scope/expiry/session', async () => {
    const result = await fulfillRequestActor(
      registeredManagerClient,
      baseFulfillParameters(),
    )
    const parsed = parseActorAuthorizationContext(result.permissionsContext)
    expect(parsed.account).toBe(account)
    expect(parsed.actor).toEqual(baseFulfillParameters().actor)
    expect(parsed.scope).toBe(actorScope.policy)
    expect(parsed.expiry).toBe(futureExpiry)
    expect(parsed.session.commitment).toBe(result.session.commitment)
    expect(parsed.session.manager.toLowerCase()).toBe(manager.toLowerCase())
    expect(parsed.session.policy.toLowerCase()).toBe(policy.toLowerCase())
  })

  test('is versioned distinctly from the legacy ERC-7715 grant-role context', () => {
    const session = defineSessionPolicy({
      account,
      manager,
      policy,
      policyConfig: encodeSessionPolicyConfig(policyConfig),
    })
    const legacyContext = toPermissionsContext({
      role: 'session',
      actor: key.k1(manager),
      session,
    })

    // The legacy (unversioned) context must not be misparsed as the new
    // actor-authorization format.
    expect(() => parseActorAuthorizationContext(legacyContext)).toThrow(
      /version tag/,
    )
    // ...and the legacy decoder is untouched / unaffected by the new format.
    expect(parsePermissionsContext(legacyContext).role).toBe('session')
  })

  test('encodes a stable, non-zero version tag', () => {
    expect(actorAuthorizationContextMagic).toMatch(/^0x[0-9a-f]{64}$/)
    expect(actorAuthorizationContextMagic).not.toBe(
      '0x0000000000000000000000000000000000000000000000000000000000000000',
    )
  })

  test('toActorAuthorizationContext / parseActorAuthorizationContext round-trip directly', () => {
    const session = defineSessionPolicy({
      account,
      manager,
      policy,
      policyConfig: encodeSessionPolicyConfig(policyConfig),
      validUntil: futureExpiry,
    })
    const actor = key.p256({
      x: '0x1000000000000000000000000000000000000000000000000000000000000000',
      y: '0x2000000000000000000000000000000000000000000000000000000000000000',
    })
    const context = toActorAuthorizationContext({
      account,
      actor,
      scope: actorScope.policy,
      expiry: futureExpiry,
      session,
    })
    const parsed = parseActorAuthorizationContext(context)
    expect(parsed.actor).toEqual(actor)
    expect(parsed.session.commitment).toBe(session.commitment)
  })
})

describe('requestActor (app-side RPC action)', () => {
  const actor = key.p256({
    x: '0x1000000000000000000000000000000000000000000000000000000000000000',
    y: '0x2000000000000000000000000000000000000000000000000000000000000000',
  })

  function requestParameters() {
    return {
      account,
      actor,
      scope: actorScope.policy,
      expiry: futureExpiry,
      policy: { version: 'session-policy-v1' as const, data: policyConfig },
    }
  }

  /** A wallet client wired to a real `fulfillRequestActor` "handler". */
  function walletClient(
    options: {
      onRequest?: (params: any) => void
      mutateResponse?: (response: any) => any
    } = {},
  ) {
    return createClient({
      chain: mainnet,
      transport: custom({
        async request({ method, params }: { method: string; params: any }) {
          if (method !== 'wallet_requestActor')
            throw new Error(`unexpected RPC: ${method}`)
          const wire = JSON.parse(JSON.stringify(params[0]))
          options.onRequest?.(wire)
          const approved = parseRequestActorParameters(wire)
          const result = await fulfillRequestActor(registeredManagerClient, {
            account: approved.account ?? account,
            chainId: approved.chainId,
            signer,
            actor: approved.actor,
            scope: approved.scope,
            expiry: approved.expiry,
            policyVersion: approved.policy.version,
            policyConfig: approved.policy.data,
            manager,
            policy,
          })
          const response = serializeRequestActorResult(result)
          return JSON.parse(
            JSON.stringify(options.mutateResponse?.(response) ?? response),
          )
        },
      }),
    })
  }

  test('round-trips a well-formed wallet response', async () => {
    const client = walletClient()
    const result = await requestActor(client, requestParameters())
    expect(result.account).toBe(account)
    expect(result.chainId).toBe(1)
    expect(result.signedAccountChanges.changes).toHaveLength(1)
    const [change] = result.signedAccountChanges.changes
    expect(change && 'actorId' in change && change.actorId).toBe(actor.actorId)

    // Compatible with the existing 8130 serialization helpers as-is.
    expect(() =>
      toAccountChangesList([result.signedAccountChanges]),
    ).not.toThrow()
  })

  test('sends only the declared request fields over the wire (no secret/RPC-option leakage)', async () => {
    let sentParams: any
    const client = walletClient({ onRequest: (p) => (sentParams = p) })
    await requestActor(client, requestParameters())
    expect(Object.keys(sentParams).sort()).toEqual(
      ['account', 'chainId', 'actor', 'expiry', 'policy', 'scope'].sort(),
    )
    expect(sentParams.manager).toBeUndefined()
    expect(sentParams.policy.manager).toBeUndefined()
    expect(sentParams.signer).toBeUndefined()
  })

  test('rejects a response for a different actor', async () => {
    const client = walletClient({
      mutateResponse: (response) => ({
        ...response,
        signedAccountChanges: {
          ...response.signedAccountChanges,
          changes: response.signedAccountChanges.changes.map((c: any) => ({
            ...c,
            actorId:
              '0x0000000000000000000000000000000000000000000000000000000000000bad',
          })),
        },
      }),
    })
    await expect(requestActor(client, requestParameters())).rejects.toThrow(
      /does not include a signed `authorizeActor` change/,
    )
  })

  test('rejects a response with a mismatched (widened) scope', async () => {
    const client = walletClient({
      mutateResponse: (response) => ({
        ...response,
        signedAccountChanges: {
          ...response.signedAccountChanges,
          changes: response.signedAccountChanges.changes.map((c: any) =>
            c.scope !== undefined
              ? {
                  ...c,
                  scope: numberToHex(actorScope.policy | actorScope.nonce),
                }
              : c,
          ),
        },
      }),
    })
    await expect(requestActor(client, requestParameters())).rejects.toThrow(
      /does not match the requested scope/,
    )
  })

  test('rejects a response with a mismatched expiry', async () => {
    const client = walletClient({
      mutateResponse: (response) => ({
        ...response,
        signedAccountChanges: {
          ...response.signedAccountChanges,
          changes: response.signedAccountChanges.changes.map((c: any) =>
            c.expiry !== undefined
              ? { ...c, expiry: numberToHex(futureExpiry + 1n) }
              : c,
          ),
        },
      }),
    })
    await expect(requestActor(client, requestParameters())).rejects.toThrow(
      /does not match the requested expiry/,
    )
  })

  test('rejects an internally inconsistent permissionsContext', async () => {
    const client = walletClient({
      mutateResponse: (response) => ({
        ...response,
        // Swap in a context bound to a different account entirely.
        permissionsContext: toActorAuthorizationContext({
          account: '0x0000000000000000000000000000000000000bad',
          actor,
          scope: actorScope.policy,
          expiry: futureExpiry,
          session: defineSessionPolicy({
            account: '0x0000000000000000000000000000000000000bad',
            manager,
            policy,
            policyConfig: encodeSessionPolicyConfig(policyConfig),
            validUntil: futureExpiry,
          }),
        }),
      }),
    })
    await expect(requestActor(client, requestParameters())).rejects.toThrow(
      /permissionsContext.*account/,
    )
  })

  test('rejects a chainId mismatch (chain binding)', async () => {
    const client = walletClient({
      mutateResponse: (response) => ({
        ...response,
        chainId: numberToHex(999),
      }),
    })
    await expect(requestActor(client, requestParameters())).rejects.toThrow(
      /different chain/,
    )
  })
})

function nativeRequest() {
  const p = baseFulfillParameters()
  return {
    account,
    chainId: 1,
    actor: p.actor,
    scope: p.scope,
    expiry: p.expiry,
    policy: { version: p.policyVersion, data: p.policyConfig },
  }
}

function responseClient(response: unknown, configuredChain = true) {
  return createClient({
    chain: configuredChain ? mainnet : undefined,
    transport: custom({
      async request() {
        return JSON.parse(JSON.stringify(response))
      },
    }),
  })
}

describe('review regressions: transport and runtime bounds', () => {
  test('all policy numbers cross a real JSON boundary, including max uint160 and uint40', () => {
    const request = {
      ...nativeRequest(),
      policy: {
        version: 'session-policy-v1' as const,
        data: {
          tokenLimits: [
            {
              token: zeroAddress,
              limit: (1n << 160n) - 1n,
              period: (1n << 40n) - 1n,
            },
          ],
          callScopes: [
            {
              target: usdc,
              selectorRules: [
                { selector: '0xa9059cbb' as const, recipients: [account] },
              ],
            },
          ],
        },
      },
    }
    const wire = JSON.parse(
      JSON.stringify(serializeRequestActorParameters(request)),
    )
    expect(wire.policy.data.tokenLimits[0].period).toBe('0xffffffffff')
    expect(parseRequestActorParameters(wire)).toEqual(request)
  })

  test.each([
    0,
    -1,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.MAX_SAFE_INTEGER + 1,
  ])('invalid chainId %s fails before signing/RPC', async (chainId) => {
    await expect(
      fulfillRequestActor(throwingClient, {
        ...baseFulfillParameters(),
        chainId,
      }),
    ).rejects.toThrow(/chainId/)
    await expect(
      requestActor(throwingClient, { ...nativeRequest(), chainId }),
    ).rejects.toThrow(/chainId/)
  })

  test.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 1n << 40n])(
    'invalid expiry %s',
    async (expiry) => {
      await expect(
        requestActor(throwingClient, { ...nativeRequest(), expiry }),
      ).rejects.toThrow()
    },
  )

  test.each([-1, 8.5, 8 + 2 ** 32, Number.NaN, 0x10000])(
    'invalid scope %s cannot be truncated with bitwise operators',
    async (scope) => {
      await expect(
        requestActor(throwingClient, { ...nativeRequest(), scope }),
      ).rejects.toThrow()
    },
  )

  test.each([
    { actorId: '0x01' },
    { actorId: `0x${'00'.repeat(32)}` },
    { authenticator: zeroAddress },
    { authenticator: '0xgg' },
    { scope: 0 },
    { policyData: '0x' },
  ])('invalid identity %o', async (patch) => {
    await expect(
      requestActor(throwingClient, {
        ...nativeRequest(),
        actor: { ...nativeRequest().actor, ...patch },
      } as never),
    ).rejects.toThrow()
  })

  test.each([
    { tokenLimits: [{ token: usdc, limit: 1n << 160n }] },
    { tokenLimits: [{ token: usdc, limit: -1n }] },
    { tokenLimits: [{ token: usdc, limit: 1n, period: 1n << 40n }] },
    { tokenLimits: [{ token: usdc, limit: 1n, gasLimit: 1n }] },
    { tokenLimits: [{ token: '0xbad', limit: 1n }] },
    { gasLimit: 1n },
    {
      callScopes: [
        {
          target: usdc,
          selectorRules: [{ selector: '0xa9059c', recipients: [] }],
        },
      ],
    },
    {
      callScopes: [
        {
          target: usdc,
          selectorRules: [{ selector: '0xa9059cbb', recipients: ['0xbad'] }],
        },
      ],
    },
    { callScopes: [{ target: usdc, valueLimit: 0n }] },
    {
      callScopes: [
        { target: usdc, selectorRules: [{ selector: '0xa9059cbb', count: 1 }] },
      ],
    },
  ])(
    'unsupported policy constraints or scalar bounds are rejected %o',
    async (data) => {
      await expect(
        requestActor(throwingClient, {
          ...nativeRequest(),
          policy: { version: 'session-policy-v1', data },
        } as never),
      ).rejects.toThrow()
      await expect(
        fulfillRequestActor(throwingClient, {
          ...baseFulfillParameters(),
          policyConfig: data,
        } as never),
      ).rejects.toThrow()
    },
  )

  test('provider mutation of request identity does not change the expected actor', async () => {
    const otherActor = key.k1(usdc)
    const result = await fulfillRequestActor(registeredManagerClient, {
      ...baseFulfillParameters(),
      actor: otherActor,
    })
    const client = createClient({
      chain: mainnet,
      transport: custom({
        async request({ params }: any) {
          Object.assign(params[0].actor, otherActor)
          return serializeRequestActorResult(result)
        },
      }),
    })
    await expect(requestActor(client, nativeRequest())).rejects.toThrow(
      /requested actor/,
    )
  })

  test('untrusted wire fields cannot become trusted wallet options', () => {
    const wire = serializeRequestActorParameters(nativeRequest())
    for (const extra of [
      { manager },
      { allowSelfPayer: true },
      { approveManagerRegistration: true },
      { signer },
    ])
      expect(() => parseRequestActorParameters({ ...wire, ...extra })).toThrow(
        /fields/,
      )
    expect(() =>
      parseRequestActorParameters({
        ...wire,
        policy: { ...wire.policy, version: 'session-policy-v2' },
      } as never),
    ).toThrow(/version/)
    expect(() =>
      parseRequestActorParameters({
        ...wire,
        policy: {
          ...wire.policy,
          data: { tokenLimits: [{ token: usdc, limit: '10' }] },
        },
      } as never),
    ).toThrow(/quantity/)
  })

  test('configured/actual transport chain disagreements never reach the signer', async () => {
    const sign = vi.fn(signer.sign)
    for (const [client, chainId] of [
      [mockClient(), 8453],
      [mockClient({ rpcChainId: '0x2' }), 1],
      [mockClient({ configuredChain: false, rpcChainId: '0x2' }), 1],
    ] as const)
      await expect(
        fulfillRequestActor(client, {
          ...baseFulfillParameters(),
          signer: { ...signer, sign },
          chainId,
        }),
      ).rejects.toThrow(/chain/i)
    expect(sign).not.toHaveBeenCalled()
  })

  test('explicit chain works without ambient client metadata and response must match it', async () => {
    const result = await fulfillRequestActor(
      mockClient({ configuredChain: false }),
      { ...baseFulfillParameters(), chainId: 1 },
    )
    const wire = serializeRequestActorResult(result)
    expect(
      (await requestActor(responseClient(wire, false), nativeRequest()))
        .chainId,
    ).toBe(1)
    await expect(
      requestActor(
        responseClient({ ...wire, chainId: '0x2' }, false),
        nativeRequest(),
      ),
    ).rejects.toThrow(/different chain/)
    await expect(
      requestActor(responseClient(wire, false), {
        ...nativeRequest(),
        chainId: undefined,
      }),
    ).rejects.toThrow(/chainId/)
  })
})

describe('review regressions: live actor protection', () => {
  test('separate approvals require true, not truthy untrusted values', async () => {
    await expect(
      fulfillRequestActor(mockClient({ managerAuthenticator: zeroAddress }), {
        ...baseFulfillParameters(),
        approveManagerRegistration: 'false' as never,
      }),
    ).rejects.toThrow(/approveManagerRegistration/)
    await expect(
      fulfillRequestActor(throwingClient, {
        ...baseFulfillParameters(),
        scope: actorScope.policy | actorScope.selfPayer,
        allowSelfPayer: 'false' as never,
      }),
    ).rejects.toThrow(/allowSelfPayer/)
  })

  test.each([manager, account])(
    'manager/self identity collision %s',
    async (address) => {
      await expect(
        fulfillRequestActor(throwingClient, {
          ...baseFulfillParameters(),
          actor: key.k1(address),
        }),
      ).rejects.toThrow(/collides/)
    },
  )

  test('live admin and different-authenticator slots are protected; same-auth scoped renewal is allowed', async () => {
    const actorAuthenticator = baseFulfillParameters().actor.authenticator
    await expect(
      fulfillRequestActor(
        mockClient({ actorAuthenticator, actorScope: 0 }),
        baseFulfillParameters(),
      ),
    ).rejects.toThrow(/live admin/)
    await expect(
      fulfillRequestActor(
        mockClient({
          actorAuthenticator: ecrecoverAuthenticator,
          actorScope: actorScope.policy,
        }),
        baseFulfillParameters(),
      ),
    ).rejects.toThrow(/different-authenticator/)
    await expect(
      fulfillRequestActor(
        mockClient({ actorAuthenticator, actorScope: actorScope.policy }),
        baseFulfillParameters(),
      ),
    ).resolves.toBeDefined()
  })

  test('admin scope is operational for an existing manager', async () => {
    const result = await fulfillRequestActor(
      mockClient({ managerScope: 0 }),
      baseFulfillParameters(),
    )
    expect(result.managerChange).toBeUndefined()
  })

  test('manager expiry equality is live; after expiry the getter returns zero and consent is required', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(1_800_000_000_000)
    try {
      const params = { ...baseFulfillParameters(), expiry: 1_800_003_600 }
      expect(
        (
          await fulfillRequestActor(
            mockClient({ managerExpiry: 1_800_000_000 }),
            params,
          )
        ).managerChange,
      ).toBeUndefined()
      const expired = mockClient({ managerExpiry: 1_799_999_999 })
      await expect(fulfillRequestActor(expired, params)).rejects.toThrow(
        /No live manager/,
      )
      expect(
        (
          await fulfillRequestActor(expired, {
            ...params,
            approveManagerRegistration: true,
          })
        ).managerChange?.scope,
      ).toBe(actorScope.operator)
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('review regressions: context and complete signed batch', () => {
  test('context cannot silently change account, expiry, policy type, or commitment', async () => {
    const result = await fulfillRequestActor(
      registeredManagerClient,
      baseFulfillParameters(),
    )
    const context = parseActorAuthorizationContext(result.permissionsContext)
    expect(() =>
      toActorAuthorizationContext({ ...context, account: usdc }),
    ).toThrow(/binding/)
    expect(() =>
      toActorAuthorizationContext({ ...context, expiry: context.expiry + 1n }),
    ).toThrow(/binding/)
    expect(() =>
      toActorAuthorizationContext({
        ...context,
        session: {
          ...context.session,
          actorPolicy: { ...context.session.actorPolicy, type: 2 },
        },
      }),
    ).toThrow(/policy type/)
    expect(() =>
      toActorAuthorizationContext({
        ...context,
        session: { ...context.session, commitment: `0x${'11'.repeat(32)}` },
      }),
    ).toThrow(/binding/)
    expect(() =>
      parseActorAuthorizationContext(`${result.permissionsContext}00`),
    ).toThrow(/Noncanonical/)
  })

  test('genuinely signed broader policy fails exact intent comparison', async () => {
    const result = await fulfillRequestActor(registeredManagerClient, {
      ...baseFulfillParameters(),
      policyConfig: { tokenLimits: [{ token: usdc, limit: 1_000_000_000n }] },
    })
    await expect(
      requestActor(
        responseClient(serializeRequestActorResult(result)),
        nativeRequest(),
      ),
    ).rejects.toThrow(/intent/)
  })

  test('self-consistent delayed activation fails v1 semantics', async () => {
    const result = await fulfillRequestActor(
      registeredManagerClient,
      baseFulfillParameters(),
    )
    const session = defineSessionPolicy({
      ...result.session.binding,
      manager,
      validAfter: 1n,
    })
    const change = authorizeActor(result.actor, {
      scope: actorScope.policy,
      expiry: futureExpiry,
      policy: session.actorPolicy,
    })
    result.signedAccountChanges = await signAccountChanges({
      signer,
      account,
      chainId: 1,
      sequence: result.signedAccountChanges.sequence,
      changes: [change],
    })
    result.permissionsContext = toActorAuthorizationContext({
      account,
      actor: result.actor,
      scope: actorScope.policy,
      expiry: futureExpiry,
      session,
    })
    await expect(
      requestActor(
        responseClient(serializeRequestActorResult(result)),
        nativeRequest(),
      ),
    ).rejects.toThrow(/intent/)
  })

  test('only the exact optional preceding manager prerequisite is accepted', async () => {
    const result = await fulfillRequestActor(
      mockClient({ managerAuthenticator: zeroAddress }),
      { ...baseFulfillParameters(), approveManagerRegistration: true },
    )
    const wire = serializeRequestActorResult(result)
    await expect(
      requestActor(responseClient(wire), nativeRequest()),
    ).resolves.toBeDefined()
    for (const patch of [
      { scope: '0x0' },
      { expiry: '0x1' },
      { policyData: '0x00' },
      { actorId: key.k1(usdc).actorId },
      { authenticator: usdc },
    ]) {
      const bad = {
        ...wire,
        signedAccountChanges: {
          ...wire.signedAccountChanges,
          changes: [
            { ...wire.signedAccountChanges.changes[0], ...patch },
            wire.signedAccountChanges.changes[1],
          ],
        },
      }
      await expect(
        requestActor(responseClient(bad), nativeRequest()),
      ).rejects.toThrow(/manager registration/)
    }
  })

  test.each([
    'overwrite',
    'duplicate',
    'revoke',
    'epoch',
    'lock',
    'unlock',
    'other-actor',
    'trailing-manager',
  ] as const)('genuinely signed %s sibling is rejected', async (attack) => {
    const result = await fulfillRequestActor(
      registeredManagerClient,
      baseFulfillParameters(),
    )
    const siblings: Record<typeof attack, AaChange> = {
      overwrite: authorizeActor(result.actor, { scope: actorScope.operator }),
      duplicate: result.change,
      revoke: { changeType: 1, actorId: result.actor.actorId },
      epoch: { changeType: 2 },
      lock: { changeType: 3, unlockDelay: 1 },
      unlock: { changeType: 4 },
      'other-actor': authorizeActor(key.k1(usdc), {
        scope: actorScope.operator,
      }),
      'trailing-manager': authorizeActor(key.k1(manager), {
        scope: actorScope.operator,
      }),
    }
    const sibling = siblings[attack]
    const signed = await signAccountChanges({
      signer,
      account,
      chainId: 1,
      sequence: result.signedAccountChanges.sequence,
      changes: [result.change, sibling],
    })
    const wire = serializeRequestActorResult(result)
    const siblingWire =
      sibling.changeType === 0
        ? serializeRequestActorResult({
            ...result,
            signedAccountChanges: { ...signed, changes: [sibling] },
          }).signedAccountChanges.changes[0]
        : { changeType: numberToHex(sibling.changeType) }
    wire.signedAccountChanges.signature = signed.signature
    const bad = {
      ...wire,
      signedAccountChanges: {
        ...wire.signedAccountChanges,
        changes: [...wire.signedAccountChanges.changes, siblingWire],
      },
    }
    await expect(
      requestActor(responseClient(bad), nativeRequest()),
    ).rejects.toThrow()
  })

  test.each([
    { channel: 'multichain' },
    { type: 'delegation' },
    { sequence: '0x0' },
    { sequence: '0x100000000ffffffff' },
    { sequence: '-1' },
    { sequence: '0x' },
    { signature: '0xgg' },
    { signature: '0x01' },
    { signature: ecrecoverAuthenticator },
    { changes: [] },
    { changes: null },
  ])('malformed or non-local-unsequenced response %o', async (patch) => {
    const result = await fulfillRequestActor(
      registeredManagerClient,
      baseFulfillParameters(),
    )
    const wire = serializeRequestActorResult(result)
    await expect(
      requestActor(
        responseClient({
          ...wire,
          signedAccountChanges: { ...wire.signedAccountChanges, ...patch },
        }),
        nativeRequest(),
      ),
    ).rejects.toThrow()
  })

  test('signature recovers admin against raw batch digest, not a message envelope', async () => {
    const result = await fulfillRequestActor(
      registeredManagerClient,
      baseFulfillParameters(),
    )
    const signed = result.signedAccountChanges
    expect(slice(signed.signature, 0, 20)).toBe(ecrecoverAuthenticator)
    const digest = hashAccountChanges({
      account,
      chainId: 1,
      sequence: signed.sequence,
      changes: signed.changes,
    })
    expect(
      await recoverAddress({
        hash: digest,
        signature: slice(signed.signature, 20),
      }),
    ).toBe(signer.address)
    const otherChain = hashAccountChanges({
      account,
      chainId: 2,
      sequence: signed.sequence,
      changes: signed.changes,
    })
    expect(
      await recoverAddress({
        hash: otherChain,
        signature: slice(signed.signature, 20),
      }),
    ).not.toBe(signer.address)
  })

  test('documented first-use preparation and serialization uses declared scope, parsed manager call and payer', async () => {
    const actorSigner = privateKeyToAccount(accounts[1].privateKey)
    const actor = key.k1(actorSigner.address)
    const policyConfig = {
      tokenLimits: [{ token: usdc, limit: 10_000_000n }],
      callScopes: [
        {
          target: usdc,
          selectorRules: [
            { selector: '0xa9059cbb' as const, recipients: [account] },
          ],
        },
      ],
    }
    const request = {
      ...nativeRequest(),
      actor,
      policy: { version: 'session-policy-v1' as const, data: policyConfig },
    }
    const result = await fulfillRequestActor(registeredManagerClient, {
      ...baseFulfillParameters(),
      actor,
      policyConfig,
    })
    const response = await requestActor(
      responseClient(serializeRequestActorResult(result)),
      request,
    )
    const context = parseActorAuthorizationContext(response.permissionsContext)
    const sessionAccount = toAccount({
      address: response.account,
      signer: actorSigner,
      actorId: context.actor.actorId,
      authenticator: context.actor.authenticator,
      scope: context.scope,
    })
    const call = context.session.executeCall({
      target: usdc,
      data: encodeFunctionData({
        abi: erc20Abi,
        functionName: 'transfer',
        args: [account, 1_000_000n],
      }),
    })
    const client = createClient({
      chain: mainnet,
      transport: custom({
        async request({ method, params }: any) {
          expect(method).toBe('eth_call')
          const { functionName } = decodeFunctionData({
            abi: keystoreAbi,
            data: params[0].data,
          })
          expect(functionName).toBe('getActorConfig')
          return encodeFunctionResult({
            abi: keystoreAbi,
            functionName: 'getActorConfig',
            result: { authenticator: zeroAddress, scope: 0, expiry: 0 },
          })
        },
      }),
    })
    const payer = { account: signer }
    const prepared = await prepareTransactionRequest(client, {
      account: sessionAccount,
      accountChanges: [response.signedAccountChanges],
      calls: encodeWalletCalls({ account: response.account, calls: [[call]] }),
      payer,
      gas: 250_000n,
      maxFeePerGas: 1_000_000_000n,
      maxPriorityFeePerGas: 1n,
    })
    expect(prepared.nonceKey).toBe(nonceKeyMax)
    expect(prepared.nonceSequence).toBe(0n)
    expect(prepared.validBefore).toBeGreaterThan(BigInt(Date.now()))
    expect(prepared.calls?.[0]?.[0]?.to.toLowerCase()).toBe(
      manager.toLowerCase(),
    )
    const serialized = await sessionAccount.signTransaction(prepared, { payer })
    const parsed = parseTransaction(serialized)
    expect(parsed.accountChanges).toEqual([
      {
        ...response.signedAccountChanges,
        changes: response.signedAccountChanges.changes.map((change) =>
          change.changeType === 0
            ? { ...change, actorId: change.actorId.toLowerCase() }
            : change,
        ),
      },
    ])
    expect(parsed.payer?.toLowerCase()).toBe(signer.address.toLowerCase())
    expect(parsed.senderAuth).toMatch(/^0x[0-9a-f]+$/)
    expect(parsed.payerAuth).toMatch(/^0x[0-9a-f]+$/)
  })
})
