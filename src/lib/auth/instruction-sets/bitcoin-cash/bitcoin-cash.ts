import { Secp256k1 } from '../../../crypto/crypto';
import {
  AuthenticationVirtualMachine,
  DebuggingStep,
  InstructionSet
} from '../../virtual-machine';
import {
  AuthenticationProgram,
  cloneStack,
  commonOperators,
  CommonProgramExternalState,
  CommonProgramInternalState,
  Ripemd160,
  Sha256
} from '../common/common';
import { BitcoinCashOpCodes } from './bitcoin-cash-opcodes';

export enum BitcoinCashAuthenticationError {}

// tslint:disable-next-line:no-empty-interface
export interface BitcoinCashAuthenticationProgramExternalState
  extends CommonProgramExternalState {}

export interface BitcoinCashAuthenticationProgramInternalState
  extends CommonProgramInternalState<BitcoinCashAuthenticationError> {}

export interface BitcoinCashAuthenticationProgramState
  extends BitcoinCashAuthenticationProgramExternalState,
    BitcoinCashAuthenticationProgramInternalState {}

export const bitcoinCashInstructionSet = (
  sha256: Sha256,
  ripemd160: Ripemd160,
  secp256k1: Secp256k1
): InstructionSet<BitcoinCashAuthenticationProgramState> => ({
  before: (state: BitcoinCashAuthenticationProgramState) => {
    // tslint:disable-next-line:no-object-mutation no-expression-statement
    state.ip++;
    // TODO: add operations[] array of opcodes executed (for isPushOnly check in P2SH validation)
    return state;
  },
  clone: (state: BitcoinCashAuthenticationProgramState) => ({
    ...(state.error !== undefined ? { error: state.error } : {}),
    blockHeight: state.blockHeight,
    blockTime: state.blockTime,
    correspondingOutputHash: state.correspondingOutputHash.slice(),
    ip: state.ip,
    lastCodeSeparator: state.lastCodeSeparator,
    locktime: state.locktime,
    outpointIndex: state.outpointIndex,
    outpointTransactionHash: state.outpointTransactionHash.slice(),
    outpointValue: state.outpointValue,
    script: state.script.slice(),
    sequenceNumber: state.sequenceNumber,
    stack: state.stack.slice(),
    transactionOutpointsHash: state.transactionOutpointsHash.slice(),
    transactionOutputsHash: state.transactionOutputsHash.slice(),
    transactionSequenceNumbersHash: state.transactionSequenceNumbersHash.slice(),
    version: state.version
  }),
  continue: (state: BitcoinCashAuthenticationProgramState) =>
    state.error === undefined && state.ip < state.script.length,
  ...commonOperators<
    BitcoinCashAuthenticationProgramState,
    BitcoinCashAuthenticationError
  >(sha256, ripemd160, secp256k1)
});

const enum PayToScriptHash {
  length = 23,
  lastElement = 22
}

const isPayToScriptHash = (lockingScript: Uint8Array) =>
  lockingScript.length === PayToScriptHash.length &&
  lockingScript[0] === BitcoinCashOpCodes.OP_HASH160 &&
  lockingScript[1] === BitcoinCashOpCodes.OP_DATA_20 &&
  lockingScript[PayToScriptHash.lastElement] === BitcoinCashOpCodes.OP_EQUAL;

/**
 * From C++ implementation:
 * Note that IsPushOnly() *does* consider OP_RESERVED to be a push-type
 * opcode, however execution of OP_RESERVED fails, so it's not relevant to
 * P2SH/BIP62 as the scriptSig would fail prior to the P2SH special
 * validation code being executed.
 */
const isPushOnly = (script: Uint8Array) =>
  // TODO: this definitely won't work... bytes inside push operations shouldn't be tested
  script.every(value => value < BitcoinCashOpCodes.OP_16);

export const debugBitcoinCashAuthenticationProgram = (
  vm: AuthenticationVirtualMachine<BitcoinCashAuthenticationProgramState>,
  program: AuthenticationProgram<BitcoinCashAuthenticationProgramExternalState>
  // tslint:disable-next-line:readonly-array
): Array<DebuggingStep<BitcoinCashAuthenticationProgramState>> => {
  const unlockingScriptResult = vm.debug(
    {
      ip: 0,
      lastCodeSeparator: -1,
      stack: [],
      // TODO: add operations: number[] to use for isPushOnly ?
      ...program.state,
      script: program.unlockingScript
    },
    'Begin unlocking script evaluation.'
  );
  const unlockingScriptFinalState =
    unlockingScriptResult[unlockingScriptResult.length - 1].state;
  // tslint:disable-next-line:no-if-statement
  if (unlockingScriptFinalState.error !== undefined) {
    return unlockingScriptResult;
  }
  const lockingScriptResult = vm.debug(
    {
      ip: 0,
      lastCodeSeparator: -1,
      stack: unlockingScriptFinalState.stack,
      ...program.state,
      script: program.lockingScript
    },
    'Begin locking script evaluation.'
  );
  const lockingScriptFinalState =
    lockingScriptResult[lockingScriptResult.length - 1].state;

  // tslint:disable-next-line:no-if-statement
  if (isPayToScriptHash(program.lockingScript)) {
    // tslint:disable-next-line:no-if-statement
    if (!isPushOnly(program.unlockingScript)) {
      return [
        ...unlockingScriptResult,
        ...lockingScriptResult,
        {
          asm: '[P2SH error]',
          description: 'P2SH error: unlockingScript must be push-only.',
          state: lockingScriptFinalState
        }
      ];
    }

    // tslint:disable-next-line:no-if-statement
    if (unlockingScriptFinalState.stack.length === 0) {
      return [
        ...unlockingScriptResult,
        ...lockingScriptResult,
        {
          asm: '[P2SH error]',
          description:
            'P2SH error: unlockingScript must not leave an empty stack.',
          state: lockingScriptFinalState
        }
      ];
    }

    const p2shStack = cloneStack(unlockingScriptFinalState.stack);
    const p2shScript = p2shStack.pop() as Uint8Array;

    const p2shScriptResult = vm.debug(
      {
        ip: 0,
        lastCodeSeparator: -1,
        stack: p2shStack,
        ...program.state,
        script: p2shScript
      },
      'Begin P2SH script evaluation.'
    );

    return [
      ...unlockingScriptResult,
      ...lockingScriptResult,
      ...p2shScriptResult
    ];
  }
  return [...unlockingScriptResult, ...lockingScriptResult];
};

// export const verifyBitcoinCashAuthenticationProgram = (
//   vm: AuthenticationVirtualMachine<BitcoinCashAuthenticationProgramState>,
//   unlockingScript: Uint8Array,
//   lockingScript: Uint8Array,
//   state: BitcoinCashAuthenticationProgramExternalState
// ): boolean => {
//   // safely create state by cloning
//   // eval the unlocking script
//   // if an error occurred, return early
//   // safely create next state, using the previous stack
//   // eval the locking script
//   // return if error occurred
//   // run P2SH validation

//   const unlockingScriptFinalState = vm.evaluate({
//     ip: 0,
//     lastCodeSeparator: -1,
//     stack: [],
//     ...state,
//     script: unlockingScript
//   });
//   // tslint:disable-next-line:no-if-statement
//   if (unlockingScriptFinalState.error !== undefined) {
//     return false;
//   }
//   const lockingScriptFinalState = vm.evaluate({
//     ip: 0,
//     lastCodeSeparator: -1,
//     stack: unlockingScriptFinalState.stack,
//     ...state,
//     script: lockingScript
//   });

//   // tslint:disable-next-line:no-if-statement
//   if (isPayToScriptHash(lockingScript)) {
//     // tslint:disable-next-line:no-if-statement
//     if (!isPushOnly(unlockingScript)) {
//       return false;
//     }

//     // tslint:disable-next-line:no-if-statement
//     if (unlockingScriptFinalState.stack.length === 0) {
//       return false;
//     }

//     const p2shStack = cloneStack(unlockingScriptFinalState.stack);
//     const p2shScript = p2shStack.pop() as Uint8Array;

//     const p2shScriptResult = vm.evaluate(
//       {
//         ip: 0,
//         lastCodeSeparator: -1,
//         stack: p2shStack,
//         ...state,
//         script: p2shScript
//       }
//     );

//     return [
//       ...unlockingScriptResult,
//       ...lockingScriptResult,
//       ...p2shScriptResult
//     ];
//   }
//   return [...unlockingScriptResult, ...lockingScriptResult];

//   const a = false;
//   return a;
// };
