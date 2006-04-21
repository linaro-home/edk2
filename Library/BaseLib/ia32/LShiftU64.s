#------------------------------------------------------------------------------
#
# Copyright (c) 2006, Intel Corporation
# All rights reserved. This program and the accompanying materials
# are licensed and made available under the terms and conditions of the BSD License
# which accompanies this distribution.  The full text of the license may be found at
# http://opensource.org/licenses/bsd-license.php
#
# THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
# WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
#
# Module Name:
#
#   LShiftU64.asm
#
# Abstract:
#
#   64-bit left shift function for IA-32
#
#------------------------------------------------------------------------------



     

.global _LShiftU64
_LShiftU64: 
    movb    12(%esp),%cl
    xorl    %eax,%eax
    movl    4(%esp),%edx
    testb   $32,%cl
    cmovz   %edx, %eax
    cmovz   8(%esp), %edx
    shldl   %cl,%eax,%edx
    shll    %cl,%eax
    ret



