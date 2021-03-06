   /* Copyright (C) 2008 The Android Open Source Project
    *
    * Licensed under the Apache License, Version 2.0 (the "License");
    * you may not use this file except in compliance with the License.
    * You may obtain a copy of the License at
    *
    * http://www.apache.org/licenses/LICENSE-2.0
    *
    * Unless required by applicable law or agreed to in writing, software
    * distributed under the License is distributed on an "AS IS" BASIS,
    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    * See the License for the specific language governing permissions and
    * limitations under the License.
    */

   /*
    * File: OP_USHR_LONG.S
    *
    * Code: Performs an unsigned shift right long operation. Uses no substitutions.
    *
    * For: ushr-long
    *
    * Description: Perform a binary shift operation using two source registers
    *              where one is the shift amount and the other is the value to shift.
    *
    * Format: AA|op CC|BB (23x)
    *
    * Syntax: op vAA, vBB, vCC
    */

    FETCH_CC    1, %eax                 # %eax<- CC
    FETCH_BB    1, %edx                 # %edx<- BB
    movsd        .LshiftMask, %xmm2     # %xmm2<- mask for the shift bits
    movss       (rFP, %eax, 4), %xmm0   # %xmm0<- vCC
    pand        %xmm2, %xmm0            # %xmm0<- masked shift bits
    movsd       (rFP, %edx, 4), %xmm1   # %xmm1<- vBB
    psrlq       %xmm0, %xmm1            # %xmm1<- shifted vBB
    movsd       %xmm1, (rFP, rINST, 4)  # vAA<- shifted vBB
    FINISH      2                       # jump to next instruction
