import { describe, expect, test } from 'vitest'
import { accounts } from '~test/constants.js'
import { privateKeyToAccount } from '../../accounts/privateKeyToAccount.js'
import { keccak256 } from '../../utils/hash/keccak256.js'
import type { TransactionSerializable8130 } from '../types/transaction.js'
import { getTransactionHash } from './getTransactionHash.js'
import { getSenderSignatureHash } from './hashTransaction.js'
import { serializeTransaction } from './serializeTransaction.js'
import { signTransaction } from './signTransaction.js'

const sender = privateKeyToAccount(accounts[0].privateKey)
const other = privateKeyToAccount(accounts[2].privateKey)
const payer = privateKeyToAccount(accounts[1].privateKey)
const bob = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' as const

const transaction: TransactionSerializable8130 = {
  chainId: 8453,
  nonceSequence: 1n,
  maxFeePerGas: 2n,
  maxPriorityFeePerGas: 1n,
  gas: 100_000n,
  calls: [[{ to: bob, data: '0xdeadbeef' }]],
}

describe('getTransactionHash', () => {
  test('default', async () => {
    const serialized = await signTransaction({ transaction, account: sender })
    const hash = await getTransactionHash({ transaction: serialized })
    expect(hash).toBe(
      getSenderSignatureHash({ ...transaction, from: sender.address }),
    )
    expect(hash).not.toBe(keccak256(serialized))
  })

  test('behavior: a named sender hashes to the sender signature hash', async () => {
    const named = { ...transaction, from: sender.address }
    expect(await getTransactionHash({ transaction: named })).toBe(
      getSenderSignatureHash(named),
    )
  })

  test('behavior: unsigned with `sender` equals the signed hash', async () => {
    const serialized = await signTransaction({ transaction, account: sender })
    expect(
      await getTransactionHash({ transaction, sender: sender.address }),
    ).toBe(await getTransactionHash({ transaction: serialized }))
  })

  test('behavior: excludes sender_auth and payer_auth', async () => {
    const base = { ...transaction, payer: payer.address }
    const hash = await getTransactionHash({
      transaction: base,
      sender: sender.address,
    })
    expect(
      await getTransactionHash({
        transaction: {
          ...base,
          payerAuth: `0x${'11'.repeat(65)}`,
          senderAuth: `0x${'22'.repeat(65)}`,
        },
        sender: sender.address,
      }),
    ).toBe(hash)
  })

  test('behavior: covers the fee fields', async () => {
    const hash = await getTransactionHash({
      transaction,
      sender: sender.address,
    })
    expect(
      await getTransactionHash({
        transaction: { ...transaction, maxFeePerGas: 3n },
        sender: sender.address,
      }),
    ).not.toBe(hash)
  })

  test('behavior: two senders signing one body get different hashes', async () => {
    const a = await signTransaction({ transaction, account: sender })
    const b = await signTransaction({ transaction, account: other })
    expect(await getTransactionHash({ transaction: a })).not.toBe(
      await getTransactionHash({ transaction: b }),
    )
  })

  test('behavior: an empty sender and the same body naming it share a hash', async () => {
    expect(
      await getTransactionHash({ transaction, sender: sender.address }),
    ).toBe(
      await getTransactionHash({
        transaction: { ...transaction, from: sender.address },
      }),
    )
  })

  test('error: unsigned without a sender', async () => {
    await expect(
      getTransactionHash({ transaction: serializeTransaction(transaction) }),
    ).rejects.toThrow('Cannot compute the transaction hash')
  })

  test('error: `sender` does not match `from`', async () => {
    await expect(
      getTransactionHash({
        transaction: { ...transaction, from: sender.address },
        sender: other.address,
      }),
    ).rejects.toThrow('does not match `transaction.from`')
  })
})
