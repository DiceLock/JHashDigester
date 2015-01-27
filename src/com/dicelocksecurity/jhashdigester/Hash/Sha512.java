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
import com.dicelocksecurity.jhashdigester.TypeSizes;

/**
  * Sha 512 hash algorithm implementation
  * 
  * @author      Angel Ferré @ DiceLock Security
  * @version     5.0.0.1
  * @since       2011-10-05
  */
public class Sha512 extends BaseHash {

  /**
   * Hash Algorithms Class enumerator name
   */
    private static final Hashes HASHNAME = Hashes.SHA_512;

  /**
   * Number of hash bits
   */
    private static final short HASHBITS = 512;
  /**
   * Number of hash bytes
   */
    private static final short HASHUCS = 64;
  /**
   * Number of hash shorts
   */
    private static final short HASHUSS = 32;
  /**
   * Number of hash ints
   */
    private static final short HASHULS = 16;
  /**
   * Number of hash unsigned 64 bits
   */
    private static final short HASH64S = 8;

  /**
   * Number of schedule words
   */
    private static final short SCHEDULENUMBER = 80;

  /**
   * Initial hash values of SHA512 
   */
    private static final long[] INITIALS = {0x6a09e667f3bcc908L, 
                                            0xbb67ae8584caa73bL, 
                                            0x3c6ef372fe94f82bL, 
                                            0xa54ff53a5f1d36f1L, 
                                            0x510e527fade682d1L, 
                                            0x9b05688c2b3e6c1fL, 
                                            0x1f83d9abfb41bd6bL, 
                                            0x5be0cd19137e2179L};

  /**
   * Computational constant values of SHA512 
   */
    private static final long[] CONSTANTS  = 
                                  {0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
                                   0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
                                   0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
                                   0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
                                   0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
                                   0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
                                   0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
                                   0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
                                   0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
                                   0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
                                   0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
                                   0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
                                   0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
                                   0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
                                   0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
                                   0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
                                   0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
                                   0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
                                   0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
                                   0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L};

  /**
   * Message schedule words for SHA512 
   */
    private long[] messageSchedule = new long[Sha512.SCHEDULENUMBER];

  /**
   * Number of block bits to compute hash
   */
    protected static final short HASHBLOCKBITS = 1024;
  /**
   * Number of block bytes to compute hash
   */
    protected static final short HASHBLOCKUCS = 128;
  /**
   * Number of block shorts to compute hash
   */
    protected static final short HASHBLOCKUSS = 64;
  /**
   * Number of block ints to compute hash
   */
    protected static final short HASHBLOCKULS = 32;
  /**
   * Number of block 64 bit to compute hash
   */
    protected static final short HASHBLOCK64S = 16;

  /**
   * Equation modulo constant value
   */
    protected static final short EQUATIONMODULO = 896;

  /**
   * Number of Sha 512 operations
   */
    protected static final short OPERATIONS = 80;

  /**
   * Array to store remaining bytes of intermediate hash operation
   */
    protected byte[] remainingBytes = new byte[Sha512.HASHBLOCKUCS];
    protected int  remainingBytesLength;

  /**
   * Total processed message length in bytes
   */
    protected long messageBitLengthHigh;
    protected long messageBitLengthLow;

  /**
   * Long shift right by n bit positions method
   * 
   * @param    x      int to be right shifted 
   * @param    n      number of bits to shift
   * @return   long:   x right shifted by n bit positions
   */
    private static long Sha512_ShiftRight(long x, long n) {

        return ((x) >>> (n));
    }
        
  /**
   * Long rotate right by n bit positions method
   * 
   * @param    x      long to be right rotated 
   * @param    n      number of bits to rotate
   * @return   long:  x right rotated by n bit positions
   */
    private static long rotr64(long x, long n) {
     
        return (((x) >>> n) | ((x) << (64 - n)));
    }

  /**
   * Sha 512 Sum 0 method
   * 
   * @param     x      long to operate with
   * @return    long:  rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39)
   */
    private static long Sha512_Sum_0(long x) {
        
        return (rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39));
    }

  /**
   * Sha 512 Sum 1 method
   * 
   * @param     x      long to operate with
   * @return    long:  rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41)
   */
    private static long Sha512_Sum_1(long x) {
        
        return (rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41));
    }

  /**
   * Sha 512 Sig 0 method
   * 
   * @param     x      long to operate with
   * @return    long:  rotr64(x, 1) ^ rotr64(x, 8) ^ this.Sha512_ShiftRight(x, 7)
   */
    private long Sha512_Sig_0(long x) {
        
        return (rotr64(x, 1) ^ rotr64(x, 8) ^ Sha512.Sha512_ShiftRight(x, 7));
    }

  /**
   * Sha 512 Sig 1 method
   * 
   * @param     x      long to operate with
   * @return    long:  rotr64(x, 19) ^ rotr64(x, 61) ^ this.Sha512_ShiftRight(x, 6)
   */
    private long Sha512_Sig_1(long x) {
        
        return (rotr64(x, 19) ^ rotr64(x, 61) ^ Sha512.Sha512_ShiftRight(x, 6));
    }

  /**
   * Execute Ch special function
   * 
   * @param   x       first int parameter
   * @param   y       second int parameter
   * @param   z       third int parameter
   * @return  int:    (x & y) ^ ((~x) & z)
   */
    private long Sha512_Function_Ch(long x, long y, long z) {

        return ((x & y) ^ ((~x) & z));
    }

  /**
   * Execute Maj special function
   * 
   * @param   x       first int parameter
   * @param   y       second int parameter
   * @param   z       third int parameter
   * @return  int:    (x & y) ^ (x & z) ^ (y & z)
   */
    private long Sha512_Function_Maj(long x, long y, long z) {
        
        return ((x & y) ^ (x & z) ^ (y & z));
    }

  /**
   * Sha 512 initial transform function
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
    private void Sha512_Operation_Ini(BaseHash_Long a, BaseHash_Long b, BaseHash_Long c, BaseHash_Long d, BaseHash_Long e, BaseHash_Long f, BaseHash_Long g, BaseHash_Long h, long temp1, long temp2, short j) {

        temp1 = h.getValue() + Sha512.Sha512_Sum_1(e.getValue()) + this.Sha512_Function_Ch(e.getValue(), f.getValue(), g.getValue()) + (Sha512.CONSTANTS[j]) + (this.messageSchedule[j]);
        temp2 = Sha512.Sha512_Sum_0(a.getValue()) + this.Sha512_Function_Maj(a.getValue(), b.getValue(), c.getValue());
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
   * Sha 512 tail transform function
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
    private void Sha512_Operation_Tail(BaseHash_Long a, BaseHash_Long b, BaseHash_Long c, BaseHash_Long d, BaseHash_Long e, BaseHash_Long f, BaseHash_Long g, BaseHash_Long h, long temp1, long temp2, short j) {

        this.messageSchedule[j] = (this.Sha512_Sig_1(this.messageSchedule[j-2]) + this.messageSchedule[j-7] + this.Sha512_Sig_0(this.messageSchedule[j-15]) + this.messageSchedule[j-16]);
        temp1 = h.getValue() + Sha512.Sha512_Sum_1(e.getValue()) + this.Sha512_Function_Ch(e.getValue(), f.getValue(), g.getValue()) + (Sha512.CONSTANTS[j]) + (this.messageSchedule[j]);
        temp2 = Sha512.Sha512_Sum_0(a.getValue()) + this.Sha512_Function_Maj(a.getValue(), b.getValue(), c.getValue());
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
   * Adds messaage length processed, if it is greater than unsigned long makes use
   * of another usigned long to store overflow
   * 
   * @param     byteLength    number of stream bytes added to compute the hash 
   */ 
    protected void AddMessageLength(int byteLength) {
          
        if ((this.messageBitLengthLow + (byteLength * TypeSizes.BYTE_BITS)) < this.messageBitLengthLow)
          // add overflow of unsigned long
          this.messageBitLengthHigh++;
        this.messageBitLengthLow += (byteLength  * TypeSizes.BYTE_BITS);
    }

  /**
   * Computes the stream block of information  
   * 
   * @param   digest    BaseCryptoRandomStream hash object
   * @param   stream    bit stream to be added to hash
   */
    protected void Compress(BaseCryptoRandomStream digest, byte[] stream) {
        BaseHash_Long a = new BaseHash_Long();
        BaseHash_Long b = new BaseHash_Long();
        BaseHash_Long c = new BaseHash_Long();
        BaseHash_Long d = new BaseHash_Long();
        BaseHash_Long e = new BaseHash_Long();
        BaseHash_Long f = new BaseHash_Long();
        BaseHash_Long g = new BaseHash_Long();
        BaseHash_Long h = new BaseHash_Long();
        long temp1 = 0, temp2 = 0;
        short i;

        // Initializing working variables
        a.setValue(digest.Get64Position(0));
        b.setValue(digest.Get64Position(1));
        c.setValue(digest.Get64Position(2));
        d.setValue(digest.Get64Position(3));
        e.setValue(digest.Get64Position(4));
        f.setValue(digest.Get64Position(5));
        g.setValue(digest.Get64Position(6));
        h.setValue(digest.Get64Position(7));

        for (i = 0; i < Sha512.HASHBLOCK64S; i++) {
          messageSchedule[i] = (((long)(stream[i*8] & 0x000000ffL) << 56) | ((long)(stream[i*8+1] & 0x000000ffL) << 48) 
                     | ((long)(stream[i*8+2] & 0x000000ffL) << 40) | ((long)(stream[i*8+3] & 0x000000ffL) << 32)  
                     | ((long)(stream[i*8+4] & 0x000000ffL) << 24) | ((long)(stream[i*8+5] & 0x000000ffL) << 16) 
                     | ((long)(stream[i*8+6] & 0x000000ffL) << 8) | ((long)(stream[i*8+7] & 0x000000ffL)));
        }

        //  0 <= t <= 19
        for (i = 0; i < 16; i++) {
          this.Sha512_Operation_Ini(a, b, c, d, e, f, g, h, temp1, temp2, i);
        }
        // 16 <= t <= 79
        for (i = 16; i < Sha512.OPERATIONS; i++) {
          this.Sha512_Operation_Tail(a, b, c, d, e, f, g, h, temp1, temp2, i);
        }

        // Upgrading hash values
        digest.Set64Position(0, digest.Get64Position(0) + a.getValue());
        digest.Set64Position(1, digest.Get64Position(1) + b.getValue());
        digest.Set64Position(2, digest.Get64Position(2) + c.getValue());
        digest.Set64Position(3, digest.Get64Position(3) + d.getValue());
        digest.Set64Position(4, digest.Get64Position(4) + e.getValue());
        digest.Set64Position(5, digest.Get64Position(5) + f.getValue());
        digest.Set64Position(6, digest.Get64Position(6) + g.getValue());
        digest.Set64Position(7, digest.Get64Position(7) + h.getValue());
    }

  /**
   * Constructor, default 
   */ 
    public Sha512() {
        super();
    }

  /**
   * Destructor
   */
    public void finalize() {
          
    }

  /**
   * Initializes common states of Sha512 algorithm
   */
    public void Initialize() {
        int i;
          
        this.messageDigest.Set64Position(0, Sha512.INITIALS[0]);
        this.messageDigest.Set64Position(1, Sha512.INITIALS[1]);
        this.messageDigest.Set64Position(2, Sha512.INITIALS[2]);
        this.messageDigest.Set64Position(3, Sha512.INITIALS[3]);
        this.messageDigest.Set64Position(4, Sha512.INITIALS[4]);
        this.messageDigest.Set64Position(5, Sha512.INITIALS[5]);
        this.messageDigest.Set64Position(6, Sha512.INITIALS[6]);
        this.messageDigest.Set64Position(7, Sha512.INITIALS[7]);
        this.remainingBytesLength = 0;
        for (i = 0; i < this.remainingBytes.length; i++) {
            this.remainingBytes[i] = 0;
        }
        this.messageBitLengthHigh = 0;
        this.messageBitLengthLow = 0;
        for (i = 0; i < Sha512.SCHEDULENUMBER; i++) {
            this.messageSchedule[i] = 0;
        }
    }

  /**
   * Adds the BaseCryptoRandomStream to the hash
   * 
   * @param     stream    bit stream to be added to the hash
   */
    public void Add(BaseCryptoRandomStream stream) {
        int startStreamByte = 0, processBytes = 0;
        int numBytes = 0;
        int i;
        byte[] subArray;

        // If bytes left from previous added stream, then they will be processed now with added data from new stream
        if (this.remainingBytesLength != 0) {
          if ((this.remainingBytesLength + stream.GetUCLength()) > ((int)this.GetUCHashBlockLength() - 1)) {
            // Setting the point to start the current stream processed
            startStreamByte = this.GetUCHashBlockLength() - this.remainingBytesLength;
            processBytes = stream.GetUCLength() - (this.GetUCHashBlockLength() - this.remainingBytesLength);

            for (i = 0; i < (this.GetUCHashBlockLength() - this.remainingBytesLength); i++) {
              this.remainingBytes[this.remainingBytesLength + i] = stream.GetUCPosition(i);
            }
            // Process remaining bytes of previous streams and 64 byte padding of current stream
            this.Compress(this.messageDigest, this.remainingBytes);
            // Updating message byte length processed
            this.AddMessageLength(this.GetUCHashBlockLength());
            // Remaining bytes of previous stream set to 0
            this.remainingBytesLength = 0;
          }
          else {
            processBytes = stream.GetUCLength();
          }
        }
        else {
          processBytes = stream.GetUCLength();
          startStreamByte = 0;
        }

        for (numBytes = 0; processBytes > ((int)this.GetUCHashBlockLength() - 1); numBytes += this.GetUCHashBlockLength()) {
          // Process the chunk
          subArray = new byte[stream.GetUCLength() - startStreamByte - numBytes];
          for (i = 0; i < subArray.length; i++) {
              subArray[i] = stream.GetUCPosition(startStreamByte + numBytes + i);
          }
          this.Compress(this.messageDigest, subArray);
          // Updating message byte length processed
          this.AddMessageLength(this.GetUCHashBlockLength()); 
          processBytes -= this.GetUCHashBlockLength();
        }

        // If remaining bytes left, they will be copied for the next added stream
        if (processBytes > 0) {
          for (i = 0; i < processBytes; i++) {
              this.remainingBytes[this.remainingBytesLength + i] = stream.GetUCPosition((stream.GetUCLength() - processBytes) + i);
          }
          this.remainingBytesLength += processBytes;
        }
    }

  /**
   * Finalizes hash 
   */
    public void Finalize() {
        int i;
          
        this.remainingBytes[this.remainingBytesLength] = (byte)0x80;
        if ((this.remainingBytesLength * TypeSizes.BYTE_BITS) % Sha512.HASHBLOCKBITS >= Sha512.EQUATIONMODULO) {
          for (i = 0; i < (this.GetUCHashBlockLength() - this.remainingBytesLength -1); i++) {
            this.remainingBytes[this.remainingBytesLength + 1 + i] = 0;
          }
          this.Compress(this.messageDigest, this.remainingBytes);
          this.AddMessageLength(this.remainingBytesLength);
          for (i = 0; i < this.GetUCHashBlockLength(); i++) {
            this.remainingBytes[i] = 0;
          }
          this.remainingBytesLength = 0;
        }
        else {
          for (i = 0; i < (this.GetUCHashBlockLength() - this.remainingBytesLength -1); i++) {
            this.remainingBytes[this.remainingBytesLength + 1 + i] = 0;
          }
        }
        this.AddMessageLength(this.remainingBytesLength); 
        this.remainingBytes[112] = (byte)((((long)this.messageBitLengthHigh) >>> 56) & 255);
        this.remainingBytes[113] = (byte)((((long)this.messageBitLengthHigh) >>> 48) & 255);
        this.remainingBytes[114] = (byte)((((long)this.messageBitLengthHigh) >>> 40) & 255);
        this.remainingBytes[115] = (byte)((((long)this.messageBitLengthHigh) >>> 32) & 255);
        this.remainingBytes[116] = (byte)((((long)this.messageBitLengthHigh) >>> 24) & 255);
        this.remainingBytes[117] = (byte)((((long)this.messageBitLengthHigh) >>> 16) & 255);
        this.remainingBytes[118] = (byte)((((long)this.messageBitLengthHigh) >>> 8) & 255);
        this.remainingBytes[119] = (byte)((((long)this.messageBitLengthHigh)) & 255);
        this.remainingBytes[120] = (byte)((((long)this.messageBitLengthLow) >>> 56) & 255);
        this.remainingBytes[121] = (byte)((((long)this.messageBitLengthLow) >>> 48) & 255);
        this.remainingBytes[122] = (byte)((((long)this.messageBitLengthLow) >>> 40) & 255);
        this.remainingBytes[123] = (byte)((((long)this.messageBitLengthLow) >>> 32) & 255);
        this.remainingBytes[124] = (byte)((((long)this.messageBitLengthLow) >>> 24) & 255);
        this.remainingBytes[125] = (byte)((((long)this.messageBitLengthLow) >>> 16) & 255);
        this.remainingBytes[126] = (byte)((((long)this.messageBitLengthLow) >>> 8) & 255);
        this.remainingBytes[127] = (byte)((((long)this.messageBitLengthLow)) & 255);
        this.Compress(this.messageDigest, this.remainingBytes);
    }

  /**
   * Gets hash length in bits
   * 
   * @return   short:   hash length in bits   
   */ 
    public short GetBitHashLength() {
          
        return Sha512.HASHBITS;
    }

  /**
   * Gets hash length in bytes
   * 
   * @return   short:   hash length in bytes   
   */ 
    public short GetUCHashLength() {
          
        return Sha512.HASHUCS;
    }

  /**
   * Gets hash length in shorts 
   * 
   * @return   short:   hash length in shorts   
   */ 
    public short GetUSHashLength() {
          
        return Sha512.HASHUSS;
    }

  /**
   * Gets hash length in ints
   * 
   * @return   short:   hash length in ints
   */ 
    public short GetULHashLength() {
          
        return Sha512.HASHULS;
    }

  /**
   * Gets hash length in longs (64 bits)
   * 
   * @return   short:   hash length in longs
   */ 
    public short Get64HashLength() {
          
        return Sha512.HASH64S;
    }

  /**
   * Gets the number of bits in the hash block to be hashed
   * 
   * @return    short:    number of bits in the hash block to be hashed
   */
    public short GetBitHashBlockLength() {
          
        return Sha512.HASHBLOCKBITS;
    }

  /**
   * Gets the number of bytes in the hash block to be hashed
   * 
   * @return    short:    number of bytes in the hash block to be hashed
   */
    public short GetUCHashBlockLength() {
          
        return Sha512.HASHBLOCKUCS;
    }

  /**
   * Gets the number of shorts in the hash block to be hashed
   * 
   * @return    short:    number of shorts in the hash block to be hashed
   */
    public short GetUSHashBlockLength() {
          
        return Sha512.HASHBLOCKUSS;
    }

  /**
   * Gets the number of ints in the hash block to be hashed
   * 
   * @return    short:    number of ints in the hash block to be hashed
   */
    public short GetULHashBlockLength() {
          
        return Sha512.HASHBLOCKULS;
    }

  /**
   * Gets the type of the object
   * 
   * @return    Hashes:     Sha 512 enumerator name
   */ 
    public Hashes GetType() {
          
        return Sha512.HASHNAME;
    }
  
}
