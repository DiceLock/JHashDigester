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
  * Sha 256 hash algorithm implementation
  * 
  * @author      Angel Ferré @ DiceLock Security
  * @version     5.0.0.1
  * @since       2011-10-05
  */
public class Sha256 extends BaseSha32 {

  /**
   * Hash Algorithms Class enumerator name
   */
    private static final Hashes HASHNAME = Hashes.SHA_256;

  /**
   * Number of hash bits
   */
    private static final short HASHBITS = 256;
  /**
   * Number of hash bytes
   */
    private static final short HASHUCS = 32;
  /**
   * Number of hash shorts
   */
    private static final short HASHUSS = 16;
  /**
   * Number of hash ints
   */
    private static final short HASHULS = 8;

  /**
   * Number of schedule words
   */
    private static final short SCHEDULENUMBER = 64;

  /**
   * Number of sha 256 operations
   */
    private static final short SHA256_OPERATIONS = 64;

  /**
   * Initial hash values of SHA256 
   */
    private static final int INITIALS[] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

  /**
   * Computational constant values of SHA256 
   */
    private static final int CONSTANTS[] = 
       {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

  /**
   * Message schedule words for SHA256 
   */
    private int[] messageSchedule = new int[Sha256.SCHEDULENUMBER];

  /**
   * Ch special function object
   */
    private static final BaseSha32_Function_Ch  function_Ch   = new BaseSha32_Function_Ch();
  /**
   * Maj special function object
   */
    private static final BaseSha32_Function_Maj function_Maj  = new BaseSha32_Function_Maj();

  /**
   * Int rotate right by n bit positions method
   * 
   * @param    x      int to be rotated to right
   * @param    n      number of bits to rotate
   * @return   int:   x rotated right by n bit positions
   */
    private int Sha256_RotateRight(int x, int n) {

        return (((x) >>> (n)) | ((x) << (32 - (n))));
    }

  /**
   * Int shift right by n bit positions method
   * 
   * @param    x      int to be shifted to right
   * @param    n      number of bits to shift
   * @return   int:   x shifted right by n bit positions
   */
    private int Sha256_ShiftRight(int x, int n) {
        
        return ((x) >>> (n));
    }

  /**
   * Sha 256 Sum 0 method
   * 
   * @param     x     int to operate with
   * @return    int:  Sha256_RotateRight(x, 2) ^ Sha256_RotateRight(x, 13) ^ Sha256_RotateRight(x, 22)
   */
    private int Sha256_Sum_0(int x) {
        return (this.Sha256_RotateRight(x, 2) ^ this.Sha256_RotateRight(x, 13) ^ this.Sha256_RotateRight(x, 22));
    }  
    
  /**
   * Sha 256 Sum 1 method
   * 
   * @param     x     int to operate with
   * @return    int:  Sha256_RotateRight(x, 6) ^ Sha256_RotateRight(x, 11) ^ Sha256_RotateRight(x, 25)
   */
    private int Sha256_Sum_1(int x) {
        return (this.Sha256_RotateRight(x, 6) ^ this.Sha256_RotateRight(x, 11) ^ this.Sha256_RotateRight(x, 25));
    }
    
  /**
   * Sha 256 Sig 0 method
   * 
   * @param     x     int to operate with
   * @return    int:  Sha256_RotateRight(x, 7) ^ Sha256_RotateRight(x, 18) ^ Sha256_ShiftRight(x, 3)
   */
    private int Sha256_Sig_0(int x) {
        return (this.Sha256_RotateRight(x, 7) ^ this.Sha256_RotateRight(x, 18) ^ this.Sha256_ShiftRight(x, 3));
    }
    
  /**
   * Sha 256 Sig 1 method
   * 
   * @param     x     int to operate with
   * @return    int:  RotateRight(x, 17) ^ Sha256_RotateRight(x, 19) ^ Sha256_ShiftRight(x, 10)
   */
    private int Sha256_Sig_1(int x) {
        return (this.Sha256_RotateRight(x, 17) ^ this.Sha256_RotateRight(x, 19) ^ this.Sha256_ShiftRight(x, 10));
    }

  /**
   * Sha 256 initial transform function
   * 
   * @param   a           int parameter by reference to be operated upon
   * @param   b           int parameter by reference to be operated upon
   * @param   c           int parameter by reference to be operated upon
   * @param   d           int parameter by reference to be operated upon
   * @param   e           int parameter by reference to be operated upon
   * @param   f           int parameter by reference to be operated upon
   * @param   g           int parameter by reference to be operated upon
   * @param   h           int parameter by reference to be operated upon
   * @param   temp1       int parameter to operate with
   * @param   temp2       int parameter to operate with
   * @param   j           int parameter to index messageSchedule and CONSTANTS arrays
   */
    private void Sha256_Operation_Ini(BaseHash_Int a, BaseHash_Int b, BaseHash_Int c, BaseHash_Int d, BaseHash_Int e, BaseHash_Int f, BaseHash_Int g, BaseHash_Int h, int temp1, int temp2, short j) {

        temp1 = h.getValue() + this.Sha256_Sum_1(e.getValue()) + Sha256.function_Ch.Execute(e.getValue(), f.getValue(), g.getValue()) + (Sha256.CONSTANTS[j]) + (this.messageSchedule[j]);
        temp2 = this.Sha256_Sum_0(a.getValue()) + Sha256.function_Maj.Execute(a.getValue(), b.getValue(), c.getValue());
        h.setValue(g.getValue());
        g.setValue(f.getValue());
        f.setValue(e.getValue());
        e.setValue(d.getValue() + temp1);
        d.setValue(c.getValue());
        c.setValue(b.getValue());
        b.setValue(a.getValue());
        a.setValue(temp1 + temp2);
    }

  /**
   * Sha 256 tail transform function
   * 
   * @param   a           int parameter by reference to be operated upon
   * @param   b           int parameter by reference to be operated upon
   * @param   c           int parameter by reference to be operated upon
   * @param   d           int parameter by reference to be operated upon
   * @param   e           int parameter by reference to be operated upon
   * @param   f           int parameter by reference to be operated upon
   * @param   g           int parameter by reference to be operated upon
   * @param   h           int parameter by reference to be operated upon
   * @param   temp1       int parameter to operate with
   * @param   temp2       int parameter to operate with
   * @param   j           int parameter to index messageSchedule and CONSTANTS arrays
   */
    private void Sha256_Operation_Tail(BaseHash_Int a, BaseHash_Int b, BaseHash_Int c, BaseHash_Int d, BaseHash_Int e, BaseHash_Int f, BaseHash_Int g, BaseHash_Int h, int temp1, int temp2, short j) {

        this.messageSchedule[j] = (this.Sha256_Sig_1(this.messageSchedule[j-2]) + this.messageSchedule[j-7] + this.Sha256_Sig_0(this.messageSchedule[j-15]) + this.messageSchedule[j-16]);
        temp1 = h.getValue() + this.Sha256_Sum_1(e.getValue()) + Sha256.function_Ch.Execute(e.getValue(), f.getValue(), g.getValue()) + (Sha256.CONSTANTS[j]) + (this.messageSchedule[j]);
        temp2 = this.Sha256_Sum_0(a.getValue()) + Sha256.function_Maj.Execute(a.getValue(), b.getValue(), c.getValue());
        h.setValue(g.getValue());
        g.setValue(f.getValue());
        f.setValue(e.getValue());
        e.setValue(d.getValue() + temp1);
        d.setValue(c.getValue());
        c.setValue(b.getValue());
        b.setValue(a.getValue());
        a.setValue(temp1 + temp2);
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
        BaseHash_Int f = new BaseHash_Int();
        BaseHash_Int g = new BaseHash_Int();
        BaseHash_Int h = new BaseHash_Int();
        int temp1 = 0;
        int temp2 = 0;
        short i;

        // Initilizing working variables
        a.setValue(digest.GetULPosition(0));
        b.setValue(digest.GetULPosition(1));
        c.setValue(digest.GetULPosition(2));
        d.setValue(digest.GetULPosition(3));
        e.setValue(digest.GetULPosition(4));
        f.setValue(digest.GetULPosition(5));
        g.setValue(digest.GetULPosition(6));
        h.setValue(digest.GetULPosition(7));

        for (i = 0; i < BaseSha32.HASHBLOCKULS; i++) {
          this.messageSchedule[i] = (stream[i*4] << 24) | (stream[i*4+1] << 16) | (stream[i*4+2] << 8) | ((stream[i*4+3] & 0x000000ff));
        }

        //  0 <= t <= 19
        for (i = 0; i < 16; i++) {
          this.Sha256_Operation_Ini(a, b, c, d, e, f, g, h, temp1, temp2, i);
        }
        // 16 <= t <= 63
        for (i = 16; i < Sha256.SHA256_OPERATIONS; i++) {
          this.Sha256_Operation_Tail(a, b, c, d, e, f, g, h, temp1, temp2, i);
        }

        // Upgrading hash values
        digest.SetULPosition(0, digest.GetULPosition(0) + a.getValue());
        digest.SetULPosition(1, digest.GetULPosition(1) + b.getValue());
        digest.SetULPosition(2, digest.GetULPosition(2) + c.getValue());
        digest.SetULPosition(3, digest.GetULPosition(3) + d.getValue());
        digest.SetULPosition(4, digest.GetULPosition(4) + e.getValue());
        digest.SetULPosition(5, digest.GetULPosition(5) + f.getValue());
        digest.SetULPosition(6, digest.GetULPosition(6) + g.getValue());
        digest.SetULPosition(7, digest.GetULPosition(7) + h.getValue());
    }

  /**
   * Constructor, default 
   */ 
    public Sha256() {
        super();
    }

  /**
   * Destructor
   */
    public void finalize() {
                                             
    }

  /**
   * Initializes common states of Sha256 algorithm
   */
    public void Initialize() {
        int i;
                                             
        this.messageDigest.SetULPosition(0, Sha256.INITIALS[0]);
        this.messageDigest.SetULPosition(1, Sha256.INITIALS[1]);
        this.messageDigest.SetULPosition(2, Sha256.INITIALS[2]);
        this.messageDigest.SetULPosition(3, Sha256.INITIALS[3]);
        this.messageDigest.SetULPosition(4, Sha256.INITIALS[4]);
        this.messageDigest.SetULPosition(5, Sha256.INITIALS[5]);
        this.messageDigest.SetULPosition(6, Sha256.INITIALS[6]);
        this.messageDigest.SetULPosition(7, Sha256.INITIALS[7]);
        this.remainingBytesLength = 0;
        for (i = 0; i < this.remainingBytes.length; i++) {
            this.remainingBytes[i] = 0;
        }
        this.messageBitLengthHigh = 0;
        this.messageBitLengthLow = 0;
        for (i = 0; i < Sha256.SCHEDULENUMBER; i++) {
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
                                             
        return Sha256.HASHBITS;                            
    }

  /**
   * Gets hash length in bytes
   * 
   * @return   short:   hash length in bytes   
   */ 
    public short GetUCHashLength() {
                                             
        return Sha256.HASHUCS;                            
    }

  /**
   * Gets hash length in shorts 
   * 
   * @return   short:   hash length in shorts   
   */ 
    public short GetUSHashLength() {
                                             
        return Sha256.HASHUSS;                            
    }

  /**
   * Gets hash length in ints
   * 
   * @return   short:   hash length in ints
   */ 
    public short GetULHashLength() {
                                             
        return Sha256.HASHULS;                            
    }

  /**
   * Gets the type of the object
   * 
   * @return    Hashes:     Sha 256 enumerator name
   */ 
    public Hashes GetType() {
                 
        return Sha256.HASHNAME;                            
    }

}
