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

import com.dicelocksecurity.jhashdigester.CryptoRandomStream.BaseCryptoRandomStream;

/**
  * Sha 1 hash algorithm implementation
  * 
  * @author      Angel Ferré @ DiceLock Security
  * @version     5.0.0.1
  * @since       2011-10-05
  */
public class Sha1 extends BaseSha32 {

  /**
   * Hash Algorithms Class enumerator name
   */
    private static final Hashes HASHNAME = Hashes.SHA_1;

  /**
   * Number of hash bits
   */
    private static final short HASHBITS = 160;
  /**
   * Number of hash bytes
   */
    private static final short HASHUCS = 20;
  /**
   * Number of hash shorts
   */
    private static final short HASHUSS = 10;
  /**
   * Number of hash ints
   */
    private static final short HASHULS = 5;

  /**
   * Number of schedule words
   */
    private static final short SCHEDULENUMBER = 80;

  /**
   * Number total of operations 
   */
    private static final short SHA1_OPERATIONS = 80;

  /**
   * Initial hash values of SHA1 
   */
    private static final int   INITIALS[] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};

  /**
   * Computational constant values of SHA1 
   */
    private static final int   CONSTANTS[] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};

  /**
   * Message schedule words for SHA1 
   */
    private int[] messageSchedule = new int[Sha1.SCHEDULENUMBER];

  /**
   * Ch special function object
   */
    private static final BaseSha32_Function_Ch          function_Ch     = new BaseSha32_Function_Ch();
  /**
   * Maj special function object
   */
    private static final BaseSha32_Function_Maj         function_Maj    = new BaseSha32_Function_Maj();
  /**
   * Parity special function object
   */
    private static final BaseSha32_Function_Sha1_Parity function_Parity = new BaseSha32_Function_Sha1_Parity();

  /**
   * Int rotate left by n bit positions method
   * 
   * @param    x      int to be rotated to left
   * @param    n      number of bits to rotate
   * @return   int:   x rotated left by n bit positions
   */
    private int Sha1_RotateLeft(int x, int n) {

        return (((x) << (n)) | ((x) >>> (32 - (n))));
    }
            
  /**
   * Sha 1 initial transform function
   * 
   * @param   function    special function
   * @param   a           int parameter by reference to be operated upon
   * @param   b           int parameter by reference to be operated upon
   * @param   c           int parameter by reference to be operated upon
   * @param   d           int parameter by reference to be operated upon
   * @param   e           int parameter by reference to be operated upon
   * @param   temp        int parameter to operate with
   * @param   j           int parameter to index messageSchedule array
   * @param   K           int parameter CONSTANT to operate with
   */
    private void Sha1_Operation_Ini(BaseSha32_BaseFunctions function, BaseHash_Int a, BaseHash_Int b, BaseHash_Int c, BaseHash_Int d, BaseHash_Int e, int temp, short j, int K) {

        temp = this.Sha1_RotateLeft(a.getValue(), 5) + function.Execute(b.getValue(), c.getValue(), d.getValue()) + e.getValue() + K + (this.messageSchedule[j]);
        e.setValue(d.getValue());
        d.setValue(c.getValue());
        c.setValue(this.Sha1_RotateLeft(b.getValue(), 30));
        b.setValue(a.getValue());
        a.setValue(temp);
    }

  /**
   * Sha 1 tail transform function
   * 
   * @param   function    special function
   * @param   a           int parameter by reference to be operated upon
   * @param   b           int parameter by reference to be operated upon
   * @param   c           int parameter by reference to be operated upon
   * @param   d           int parameter by reference to be operated upon
   * @param   e           int parameter by reference to be operated upon
   * @param   temp        int parameter to operate with
   * @param   j           int parameter to index messageSchedule array
   * @param   K           int parameter CONSTANT to operate with
   */
    private void Sha1_Operation_Tail(BaseSha32_BaseFunctions function, BaseHash_Int a, BaseHash_Int b, BaseHash_Int c, BaseHash_Int d, BaseHash_Int e, int temp, short j, int K) {
    
        this.messageSchedule[j] = (this.Sha1_RotateLeft(this.messageSchedule[j-3] ^ this.messageSchedule[j-8] ^ this.messageSchedule[j-14] ^ this.messageSchedule[j-16], 1));
        temp = this.Sha1_RotateLeft(a.getValue(), 5) + function.Execute(b.getValue(), c.getValue(), d.getValue()) + e.getValue() + K + (this.messageSchedule[j]);
        e.setValue(d.getValue());
        d.setValue(c.getValue());
        c.setValue(this.Sha1_RotateLeft(b.getValue(), 30));
        b.setValue(a.getValue());
        a.setValue(temp);
    }

  /**
   * Computes the stream block of information  
   * 
   * @param   digest    BaseCryptoRandomStream hash object
   * @param   stream    bit stream to be added to hash
   */
    protected void Compress(BaseCryptoRandomStream digest, byte[] stream) {
        BaseHash_Int a = new BaseHash_Int();
        BaseHash_Int b = new BaseHash_Int();
        BaseHash_Int c = new BaseHash_Int();
        BaseHash_Int d = new BaseHash_Int();
        BaseHash_Int e = new BaseHash_Int();
        int temp = 0;
        short i;

        // Initializing working variables
        a.setValue(digest.GetULPosition(0));
        b.setValue(digest.GetULPosition(1));
        c.setValue(digest.GetULPosition(2));
        d.setValue(digest.GetULPosition(3));
        e.setValue(digest.GetULPosition(4));

        for (i = 0; i < BaseSha32.HASHBLOCKULS; i++) {
          this.messageSchedule[i] = ((((int)stream[i*4]) << 24) | (((int)stream[i*4+1]) << 16) | (((int)stream[i*4+2]) << 8) | ((int)stream[i*4+3] & 0x000000ff));
        }
        //  0 <= t < 20
        for (i = 0; i < 16; i++) {
          this.Sha1_Operation_Ini(Sha1.function_Ch, a, b, c, d, e, temp, i, Sha1.CONSTANTS[0]);
        }
        for (i = 16; i < 20; i++) {
          this.Sha1_Operation_Tail(Sha1.function_Ch, a, b, c, d, e, temp, i, Sha1.CONSTANTS[0]);
        }
        // 20 <= t <= 39
        for (i = 20; i < 40; i++) {
          this.Sha1_Operation_Tail(Sha1.function_Parity, a, b, c, d, e, temp, i, Sha1.CONSTANTS[1]);
        }
        // 40 <= t <= 59
        for (i = 40; i < 60; i++) {
          this.Sha1_Operation_Tail(Sha1.function_Maj, a, b, c, d, e, temp, i, Sha1.CONSTANTS[2]);
        }
        // 60 <= t <= 79
        for (i = 60; i < Sha1.SHA1_OPERATIONS; i++) {
          this.Sha1_Operation_Tail(Sha1.function_Parity, a, b, c, d, e, temp, i, Sha1.CONSTANTS[3]);
        }

        // Upgrading hash values
        digest.SetULPosition(0, digest.GetULPosition(0) + a.getValue());
        digest.SetULPosition(1, digest.GetULPosition(1) + b.getValue());
        digest.SetULPosition(2, digest.GetULPosition(2) + c.getValue());
        digest.SetULPosition(3, digest.GetULPosition(3) + d.getValue());
        digest.SetULPosition(4, digest.GetULPosition(4) + e.getValue());
    }

  /**
   * Constructor, default 
   */ 
    public Sha1() {
        super();
    }

  /**
   * Destructor
   */
    public void finalize() {
        
    }

  /**
   * Initializes common states of Sha1 algorithm
   */
    public void Initialize() {
        int i;
        
        this.messageDigest.SetULPosition(0, Sha1.INITIALS[0]);
        this.messageDigest.SetULPosition(1, Sha1.INITIALS[1]);
        this.messageDigest.SetULPosition(2, Sha1.INITIALS[2]);
        this.messageDigest.SetULPosition(3, Sha1.INITIALS[3]);
        this.messageDigest.SetULPosition(4, Sha1.INITIALS[4]);
        this.remainingBytesLength = 0;
        for (i = 0; i < this.remainingBytes.length; i++) {
            this.remainingBytes[i] = 0;
        }
        this.messageBitLengthHigh = 0;
        this.messageBitLengthLow = 0;
        for (i = 0; i < Sha1.SCHEDULENUMBER; i++) {
            this.messageSchedule[i] = 0;
        }
    }

  /**
   * Finalizes hash 
   */
    public void Finalize() {
        
        super.Finalize();
    }

  /**
   * Gets hash length in bits
   * 
   * @return   short:   hash length in bits   
   */ 
    public short GetBitHashLength() {
        
        return Sha1.HASHBITS;        
    }

  /**
   * Gets hash length in bytes
   * 
   * @return   short:   hash length in bytes   
   */ 
    public short GetUCHashLength() {
        
        return Sha1.HASHUCS;        
    }

  /**
   * Gets hash length in shorts 
   * 
   * @return   short:   hash length in shorts   
   */ 
    public short GetUSHashLength() {
        
        return Sha1.HASHUSS;        
    }

  /**
   * Gets hash length in ints
   * 
   * @return   short:   hash length in ints
   */ 
    public short GetULHashLength() {
        
        return Sha1.HASHULS;        
    }

  /**
   * Gets the type of the object
   * 
   * @return    Hashes:     Sha 1 enumerator name
   */ 
    public Hashes GetType() {

        return Sha1.HASHNAME;        
    }
  
}
