//
// Creator:    http://www.dicelocksecurity.com
// Version:    vers.5.0.0.1
//
// Copyright 2011 DiceLock Security, LLC. All rights reserved.
//
//                               DISCLAIMER
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
// OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
// ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// DICELOCK IS A REGISTERED TRADEMARK OR TRADEMARK OF THE OWNERS.
// 
// Environment:
// java version "1.6.0_29"
// Java(TM) SE Runtime Environment (build 1.6.0_29-b11)
// Java HotSpot(TM) Server VM (build 20.4-b02, mixed mode)
// 

package com.dicelocksecurity.jhashdigester.Hash;

/**
 * Base Ripemd hash algorithm special functions
 *
 * @author      Angel Ferré @ DiceLock Security
 * @version     5.0.0.1
 * @since       2011-10-03
 */
public abstract class BaseRipemd_BaseFunctions {

    /**
     * Constructor, default
     */
    public BaseRipemd_BaseFunctions() {
        super();
    }

    /**
     * Execute special function
     *
     * @param   x       first int parameter
     * @param   y       second int parameter
     * @param   z       third int parameter
     * @return  int:    special computation of x, y and z
     */
    abstract public int Execute(int x, int y, int z);

    /**
     * Rotates an int value to the left by n bit positions
     *
     * @param   x       int to be rotated to the left
     * @param   n       n number of bits to rotate x int
     * @return  int:    x rotated by n postions to the left
     */
    public int Ripemd_RotateLeft(int x, int n) {

        return ((x << n) | (x >>> (32 - n)));
    }
}
