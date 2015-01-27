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
  * Base ripemd hash algorithm class 
  * 
  * @author      Angel Ferré @ DiceLock Security
  * @version     5.0.0.1
  * @since       2011-10-03
  */
public abstract class BaseRipemd extends BaseHash {

    protected static final short RIPEMD_DATAUCHARS = 64;
    protected static final short RIPEMD_DATAULONGS = 16;
    protected static final short RIPEMD_DATASHIFT = 4;

  /**
   * Number of block bits to compute hash
   */ 
    protected static final short HASHBLOCKBITS = 512;
  /**
   * Number of block unsigned chars to compute hash
   */ 
    protected static final short HASHBLOCKUCS = 64;
  /**
   * Number of block unsigned short ints to compute hash
   */ 
    protected static final short HASHBLOCKUSS = 32;
  /**
   * Number of block unsigned long ints to compute hash
   */ 
    protected static final short HASHBLOCKULS = 16;

  /**
   * Array to store remaining bytes of intermediate hash operation
   */ 
    protected byte[] remainingBytes = new byte[RIPEMD_DATAUCHARS];
    protected long remainingBytesLength;

  /**
   * Total processed message length in bytes
   */ 
    protected long messageByteLengthHigh;
    protected long messageByteLengthLow;

  /**
   * Common operation values to all RIPEMD algorithms
   */ 
    protected static final int CONSTANT0 = 0x00000000;
    protected static final int CONSTANT1 = 0x5A827999;
    protected static final int CONSTANT2 = 0x6ED9EBA1;
    protected static final int CONSTANT3 = 0x8F1BBCDC;
    protected static final int CONSTANT5 = 0x50A28BE6;
    protected static final int CONSTANT6 = 0x5C4DD124;
    protected static final int CONSTANT7 = 0x6D703EF3;
    protected static final int CONSTANT9 = 0x00000000;

  /**
   * Amounts of rotate left
   */ 
    protected static final short RL_0_15[] =
    { 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8 };
    protected static final short RL_16_31[] =
    { 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12 };
    protected static final short RL_32_47[] =
    { 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5 };
    protected static final short RL_48_63[] =
    { 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12 };
  /**
   * Amounts of prime rotate left
   */ 
    protected static final short PRIME_RL_0_15[] =
    { 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6 };
    protected static final short PRIME_RL_16_31[] =
    { 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11 };
    protected static final short PRIME_RL_32_47[] =
    { 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5 };
    protected static final short PRIME_RL_48_63[] =
    { 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8 };

  /**
   * Initial states of all Ripemd algorithms
   */ 
    protected static final int INISTATE0 = 0x67452301;
    protected static final int INISTATE1 = 0xEFCDAB89;
    protected static final int INISTATE2 = 0x98BADCFE;
    protected static final int INISTATE3 = 0X10325476;
    
  /**
   * Swaps final digest to accomodate to big endian coding
   */ 
    private void SwapFinalDigest() {
        byte tmp;
      
        for (int i = 0; i < this.messageDigest.GetULLength(); i++) {
          tmp = this.messageDigest.GetUCPosition(i * 4);
          this.messageDigest.SetUCPosition(i * 4, this.messageDigest.GetUCPosition((i * 4) + 3));
          this.messageDigest.SetUCPosition((i * 4) + 3, tmp);
          tmp = this.messageDigest.GetUCPosition((i * 4) + 1);
          this.messageDigest.SetUCPosition((i * 4) + 1, this.messageDigest.GetUCPosition((i * 4) + 2));
          this.messageDigest.SetUCPosition((i * 4) + 2, tmp);
        }
    }

  /**
   * Adds messaage length processed, if it is greater than unsigned long makes use
   * of another usigned long to store overflow
   * 
   * @param     byteLength    number of stream bytes added to compute the hash 
   */ 
    protected void AddMessageLength(long byteLength) {

        if ((this.messageByteLengthLow + byteLength) < this.messageByteLengthLow) {
          // add overflow of unsigned long
          this.messageByteLengthHigh++;
        }          
        this.messageByteLengthLow += byteLength;
    }

  /**
   * Computes the stream of information
   * 
   * @param     stream     portion of bit stream to be added to ciompute the hash
   */ 
    abstract protected void Compress(int[] stream);

  /**
   * Constructor, default 
   */ 
    public BaseRipemd() {
        super();

        this.remainingBytesLength = 0;
		    this.messageByteLengthHigh = 0;
		    this.messageByteLengthLow = 0;
    }

  /**
   * Destructor
   */ 
    public void finalize() {
      
		    this.remainingBytesLength = 0;
		    this.messageByteLengthHigh = 0;
		    this.messageByteLengthLow = 0;
    }

  /**
   * Initializes common states of all Ripemd algorithms 
   */ 
    public void Initialize() {
      
		    this.messageDigest.SetULPosition(0, BaseRipemd.INISTATE0);
		    this.messageDigest.SetULPosition(1, BaseRipemd.INISTATE1);
		    this.messageDigest.SetULPosition(2, BaseRipemd.INISTATE2);
		    this.messageDigest.SetULPosition(3, BaseRipemd.INISTATE3);
		    this.remainingBytesLength = 0;
		    this.messageByteLengthHigh = 0;
		    this.messageByteLengthLow = 0;
    }

  /**
   * Adds the BaseCryptoRandomStream to the hash
   * 
   * @param     stream    bit stream that is added to produce the hash
   */ 
    public void Add(BaseCryptoRandomStream stream) {
		    int[] chunk = new int[BaseRipemd.RIPEMD_DATAULONGS];
		    int startStreamByte = 0, numBytes = 0, processBytes = 0;
		    int i, j;
		    byte[] pointerUC;

		    // If bytes left from previous added stream, then they will be processed now with added data from new stream
		    if (this.remainingBytesLength != 0) {
			    if ((this.remainingBytesLength + stream.GetUCLength()) > (BaseRipemd.RIPEMD_DATAUCHARS - 1)) {
				    // Setting the point to start the current stream processed
				    startStreamByte = (int)(BaseRipemd.RIPEMD_DATAUCHARS - this.remainingBytesLength);
				    processBytes = (int)(stream.GetUCLength() - (BaseRipemd.RIPEMD_DATAUCHARS - this.remainingBytesLength));

            for (i = 0; i < (BaseRipemd.RIPEMD_DATAUCHARS - this.remainingBytesLength); i++) {
              this.remainingBytes[((int)this.remainingBytesLength) + i] = stream.GetUCPosition(i);
            }
				    pointerUC = this.remainingBytes;
            j = 0;
				    for (i = 0; i < BaseRipemd.RIPEMD_DATAULONGS; i++) {
					    chunk[i] = ((int)((pointerUC[j + 3] << 24)) | (int)(pointerUC[j + 2] << 16) | (int)(pointerUC[i + 1] << 8) | (int)(pointerUC[i]));
				      j += BaseRipemd.RIPEMD_DATASHIFT;
				    }
				    // Process remaining bytes of previous streams adn 64 byte padding of current stream
				    this.Compress(chunk);
				    // Updating message byt length processed
				    this.AddMessageLength(BaseRipemd.RIPEMD_DATAUCHARS);
				    // Remaining bytes of previous strema set to 0
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

        j = 0;
		    for (numBytes = processBytes; numBytes > (BaseRipemd.RIPEMD_DATAUCHARS - 1); numBytes -= BaseRipemd.RIPEMD_DATAUCHARS) {
			    for (i = 0; i < BaseRipemd.RIPEMD_DATAULONGS; i++) {
			      j = startStreamByte + (processBytes - numBytes) + (i<<2);
			      chunk[i] = ((int)(stream.GetUCPosition(j + 3) << 24) | ((int)(stream.GetUCPosition(j + 2) << 16)) | ((int)(stream.GetUCPosition(j + 1) << 8)) | ((int)stream.GetUCPosition(j)));
			    }
			    this.Compress(chunk);
			    // Updating message byt length processed
			    this.AddMessageLength(BaseRipemd.RIPEMD_DATAUCHARS); 
		    }

		    // If remaining bytes left, they will be copied for the next added stream
		    if (numBytes > 0) {
          for (i = 0; i < numBytes; i++) {
            this.remainingBytes[((int)this.remainingBytesLength) + i] = stream.GetUCPosition(stream.GetUCLength() - numBytes + i);
          }
			    this.remainingBytesLength += numBytes;
		    }
    }

  /**
   * Finalize the hash
   */ 
    public void Finalize() {
        int i, j;
		int[] X = new int[BaseRipemd.RIPEMD_DATAULONGS];
		byte[] leftBytes;

		if (this.remainingBytesLength > 0) {
			    this.AddMessageLength(this.remainingBytesLength);
			    leftBytes = this.remainingBytes;
        }
		else {
			    leftBytes = null;
		}

        for (i = 0; i < X.length; i++) {
          X[i] = 0;
        }

		    // put bytes into X 
        j = 0;
		    for (i = 0; i < (this.messageByteLengthLow & 63); i++) {
			    // byte i goes into word X[i div 4] at pos.  8*(i mod 4)  
			    X[i >>>2 ] ^= (leftBytes[j] << (8 * (i & 3)));
          j++;
		    }

    		// append the bit m_n == 1 
    		X[(int)((this.messageByteLengthLow >>> 2) % BaseRipemd.RIPEMD_DATAULONGS)] ^= (1 << (8*(this.messageByteLengthLow & 3) + 7));

    		if ((this.messageByteLengthLow % BaseRipemd.RIPEMD_DATAUCHARS) > 55) {
			    // length goes to next block 
			    this.Compress(X);
          for (i = 0; i < BaseRipemd.RIPEMD_DATAULONGS; i++) {
            X[i] = 0;                                                           
          }
		    }

		    // append length in bits
		    X[BaseRipemd.RIPEMD_DATAULONGS - 2] = (int)(this.messageByteLengthLow << 3);
		    X[BaseRipemd.RIPEMD_DATAULONGS - 1] = (int)((this.messageByteLengthLow >>> 29) | (this.messageByteLengthHigh << 3));
		    this.Compress(X);
        this.SwapFinalDigest();
    }

  /**
   * Gets the number of bits in the hash block to be hashed
   * 
   * @return    short:    number of bits in the hash block to be hashed
   */ 
    public short GetBitHashBlockLength() {
      
        return BaseRipemd.HASHBLOCKBITS;
    }

  /**
   * Gets the number of bytes in the hash block to be hashed
   * 
   * @return    short:    number of bytes in the hash block to be hashed
   */ 
    public short GetUCHashBlockLength() {
      
        return BaseRipemd.HASHBLOCKUCS;
    }

  /**
   * Gets the number of shorts in the hash block to be hashed
   * 
   * @return    short:    number of shorts in the hash block to be hashed
   */ 
    public short GetUSHashBlockLength() {
      
        return BaseRipemd.HASHBLOCKUSS;
    }

  /**
   * Gets the number of unsigned long ints in the hash block to be hashed
   * 
   * @return    short:    number of ints in the hash block to be hashed
   */ 
    public short GetULHashBlockLength() {
      
        return BaseRipemd.HASHBLOCKULS;
    }
}
