import type { Address } from 'abitype'
import { BaseError } from '../../errors/base.js'
import type { ErrorType } from '../../errors/utils.js'
import type { Hash, Hex } from '../../types/misc.js'
import { isAddressEqual } from '../../utils/address/isAddressEqual.js'
import type { TransactionSerializable8130 } from '../types/transaction.js'
import {
  type GetSenderSignatureHashErrorType,
  getSenderSignatureHash,
} from './hashTransaction.js'
import {
  type ParseTransactionErrorType,
  parseTransaction,
} from './parseTransaction.js'
import { recoverSenderAddress } from './recoverSender.js'

export type GetTransactionHashParameters = {
  /**
   * The transaction: a serialized `0x79` transaction or a serializable one.
   * `senderAuth` and `payerAuth` do not affect the hash and may be omitted.
   */
  transaction: TransactionSerializable8130 | Hex
  /**
   * The resolved sender. Required when `transaction.from` is empty and the
   * transaction is unsigned; otherwise the sender is recovered from
   * `senderAuth`. Must equal `transaction.from` when both are set.
   */
  sender?: Address | undefined
}

export type GetTransactionHashErrorType =
  | GetSenderSignatureHashErrorType
  | ParseTransactionErrorType
  | ErrorType

/**
 * Computes the EIP-8130 transaction hash: the sender signature hash with the
 * resolved sender in the `sender` slot.
 *
 * ```
 * keccak256(AA_TX_TYPE || rlp([
 *   chain_id, resolved_sender, nonce_key, nonce_sequence, valid_after, valid_before,
 *   max_priority_fee_per_gas, max_fee_per_gas, gas_limit,
 *   account_changes, calls, metadata, payer
 * ]))
 * ```
 *
 * Unlike other transaction types, this is not `keccak256` of the encoding. It
 * excludes `sender_auth` and `payer_auth`, so it is known before either
 * signature exists and does not change when either is re-signed. It covers the
 * fee fields, so a fee bump changes it.
 *
 * @example
 * import { getTransactionHash } from 'viem/eip8130'
 *
 * // Before signing: name the sender.
 * const hash = await getTransactionHash({ transaction, sender: account.address })
 *
 * // From signed bytes: the sender is recovered when `from` is empty.
 * const hash = await getTransactionHash({ transaction: serialized })
 */
export async function getTransactionHash(
  parameters: GetTransactionHashParameters,
): Promise<Hash> {
  const transaction =
    typeof parameters.transaction === 'string'
      ? parseTransaction(parameters.transaction)
      : parameters.transaction
  const { sender } = parameters

  if (sender && transaction.from && !isAddressEqual(sender, transaction.from))
    throw new BaseError(
      `\`sender\` (${sender}) does not match \`transaction.from\` (${transaction.from}).`,
    )

  const from =
    transaction.from ??
    sender ??
    (await recoverSenderAddress({ transaction }).catch((error) => {
      throw new BaseError(
        'Cannot compute the transaction hash: `transaction.from` is empty and the sender could not be recovered from `senderAuth`. Pass `sender` for an unsigned transaction.',
        { cause: error },
      )
    }))

  return getSenderSignatureHash({ ...transaction, from, to: 'hex' })
}
