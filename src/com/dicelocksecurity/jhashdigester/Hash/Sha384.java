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
import com.dicelocksecurity.jhashdigester.CryptoRandomStream.DefaultCryptoRandomStream;
import com.dicelocksecurity.jhashdigester.TypeSizes;

/**
 * Sha 384 hash algorithm implementation
 *
 * @author      Angel Ferré @ DiceLock Security
 * @version     5.0.0.1
 * @since       2011-10-05
 */
public class Sha384 extends Sha512 {

  /**
   * Hash Algorithms Class enumerator name
   */
    private static final Hashes HASHNAME = Hashes.SHA_384;

  /**
   * Number of hash bits
   */
    private static final short HASHBITS = 384;
  /**
   * Number of hash bytes
   */
    private static final short HASHUCS = 48;
  /**
   * Number of hash shorts
   */
    private static final short HASHUSS = 24;
  /**
   * Number of hash ints
   */
    private static final short HASHULS = 12;
  /**
   * Number of hash unsigned 64 bits
   */
    private static final short HASH64S = 6;

  /**
   * Initial hash values of SHA512 
   */
    private static final long[] INITIALS = 
                                    {0xcbbb9d5dc1059ed8L, 
                                     0x629a292a367cd507L, 
                                     0x9159015a3070dd17L, 
                                     0x152fecd8f70e5939L, 
                                     0x67332667ffc00b31L, 
                                     0x8eb44a8768581511L, 
                                     0xdb0c2e0d64f98fa7L, 
                                     0x47b5481dbefa4fa4L};

  /**
   * Pointer to BaseCryptoRandomStream digest for SHA 384 hash algorithm
   */
    private BaseCryptoRandomStream workingDigest512; 
    
  /**
   * Boolean pointing if meesaageDigest for SHA 512 has been created automatically
   */
    private boolean autoWorkingDigest;
    
  /**
   * Constructor, default 
   */ 
    public Sha384() {
        super();

        this.workingDigest512 = null;
        this.autoWorkingDigest = false;
    }

  /**
   * Destructor
   */
    public void finalize() {
          
        if (autoWorkingDigest) {
          this.workingDigest512 = null;
          this.autoWorkingDigest = false;
        }
    }

  /**
   * Set the Working Digest  BaseCryptoRandomStream for underlying SHA512 algorithm
   * 
   * @param   workDigest      BaseCryptoRandomStream working digest to compute underlying Sha 512 hash algorithm
   */
    public void SetWorkingDigest(BaseCryptoRandomStream workDigest) {
          
        this.workingDigest512 = workDigest;
    }

  /**
   * Get the Working Digest  BaseCryptoRandomStream for underlying SHA512 algorithm length in bits
   * 
   * @return    short:    underlying Sha 512 digest length in bits
   */
    public short GetWorkingDigestBitLength() {
          
        return super.GetBitHashLength();
    }

  /**
   * Get the Working Digest  BaseCryptoRandomStream for underlying SHA512 algorithm length in bytes
   * 
   * @return    short:    underlying Sha 512 digest length in bytes
   */
    public short GetWorkingDigestUCLength() {
          
        return super.GetUCHashLength();
    }

  /**
   * Get the Working Digest  BaseCryptoRandomStream for underlying SHA512 algorithm length in shorts
   * 
   * @return    short:    underlying Sha 512 digest length in shorts
   */
    public short GetWorkingDigestUSLength() {
          
        return super.GetUSHashLength();
    }

  /**
   * Get the Working Digest  BaseCryptoRandomStream for underlying SHA512 algorithm length in ints
   * 
   * @return    short:    underlying Sha 512 digest length in ints
   */
    public short GetWorkingDigestULLength() {
          
        return super.GetULHashLength();
    }

  /**
   * Initializes common states of Sha384 algorithm
   */
    public void Initialize() {
          
        if (this.workingDigest512 == null) {
          this.workingDigest512 = new DefaultCryptoRandomStream();
          this.workingDigest512.SetCryptoRandomStreamUC(this.GetWorkingDigestUCLength());
          this.autoWorkingDigest = true;
        }
        this.workingDigest512.Set64Position(0, Sha384.INITIALS[0]);
        this.workingDigest512.Set64Position(1, Sha384.INITIALS[1]);
        this.workingDigest512.Set64Position(2, Sha384.INITIALS[2]);
        this.workingDigest512.Set64Position(3, Sha384.INITIALS[3]);
        this.workingDigest512.Set64Position(4, Sha384.INITIALS[4]);
        this.workingDigest512.Set64Position(5, Sha384.INITIALS[5]);
        this.workingDigest512.Set64Position(6, Sha384.INITIALS[6]);
        this.workingDigest512.Set64Position(7, Sha384.INITIALS[7]);
        this.remainingBytesLength = 0;
        this.messageBitLengthHigh = 0;
        this.messageBitLengthLow = 0;
    }

  /**
   * Adds the BaseCryptoRandomStream to the hash
   * 
   * @param     stream    bit stream to be added to the hash
   */
    public void Add(BaseCryptoRandomStream stream) {
        int startStreamByte = 0, processBytes = 0;
        int numBytes = 0;
        int i = 0;
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
            // Process remaining bytes of previous streams adn 64 byte padding of current stream
            this.Compress(this.workingDigest512, this.remainingBytes);
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
          this.Compress(this.workingDigest512, subArray);
          // Updating message byte length processed
          this.AddMessageLength(this.GetUCHashBlockLength()); 
          processBytes -= this.GetUCHashBlockLength();
        }

        // If remaining bytes left, they will be copied for the next added stream
        if (processBytes > 0) {
          for (i = 0; i < processBytes; i++) {
            this.remainingBytes[this.remainingBytesLength + i] = stream.GetUCPosition(stream.GetUCLength() - processBytes + i);
          }
          this.remainingBytesLength += processBytes;
        }
        for (i = 0; i < this.Get64HashLength(); i++) {
          this.messageDigest.Set64Position(i, this.workingDigest512.Get64Position(i));
        }
    }

  /**
   * Finalizes hash 
   */
    public void Finalize() {
        short i;

        this.remainingBytes[this.remainingBytesLength] = (byte)0x80;
        if ((this.remainingBytesLength * TypeSizes.BYTE_BITS) % Sha512.HASHBLOCKBITS >= Sha512.EQUATIONMODULO) {
          for (i = 0; i < (this.GetUCHashBlockLength() - this.remainingBytesLength -1); i++) {
            this.remainingBytes[this.remainingBytesLength + 1 + i] = 0;
          }
          this.Compress(this.workingDigest512, this.remainingBytes);
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
        this.remainingBytes[112] = (byte)((((long)this.messageBitLengthHigh) >> 56) & 255);
        this.remainingBytes[113] = (byte)((((long)this.messageBitLengthHigh) >> 48) & 255);
        this.remainingBytes[114] = (byte)((((long)this.messageBitLengthHigh) >> 40) & 255);
        this.remainingBytes[115] = (byte)((((long)this.messageBitLengthHigh) >> 32) & 255);
        this.remainingBytes[116] = (byte)((((long)this.messageBitLengthHigh) >> 24) & 255);
        this.remainingBytes[117] = (byte)((((long)this.messageBitLengthHigh) >> 16) & 255);
        this.remainingBytes[118] = (byte)((((long)this.messageBitLengthHigh) >> 8) & 255);
        this.remainingBytes[119] = (byte)((((long)this.messageBitLengthHigh)) & 255);
        this.remainingBytes[120] = (byte)((((long)this.messageBitLengthLow) >> 56) & 255);
        this.remainingBytes[121] = (byte)((((long)this.messageBitLengthLow) >> 48) & 255);
        this.remainingBytes[122] = (byte)((((long)this.messageBitLengthLow) >> 40) & 255);
        this.remainingBytes[123] = (byte)((((long)this.messageBitLengthLow) >> 32) & 255);
        this.remainingBytes[124] = (byte)((((long)this.messageBitLengthLow) >> 24) & 255);
        this.remainingBytes[125] = (byte)((((long)this.messageBitLengthLow) >> 16) & 255);
        this.remainingBytes[126] = (byte)((((long)this.messageBitLengthLow) >> 8) & 255);
        this.remainingBytes[127] = (byte)((((long)this.messageBitLengthLow)) & 255);
        this.Compress(this.workingDigest512, this.remainingBytes);
        for (i = 0; i < this.Get64HashLength(); i++) {
          this.messageDigest.Set64Position(i, this.workingDigest512.Get64Position(i));
        }
    }

  /**
   * Gets hash length in bits
   * 
   * @return   short:   hash length in bits   
   */ 
    public short GetBitHashLength() {
          
        return Sha384.HASHBITS;
    }

  /**
   * Gets hash length in bytes
   * 
   * @return   short:   hash length in bytes   
   */ 
    public short GetUCHashLength() {
          
        return Sha384.HASHUCS;
    }

  /**
   * Gets hash length in shorts 
   * 
   * @return   short:   hash length in shorts   
   */ 
    public short GetUSHashLength() {
          
        return Sha384.HASHUSS;
    }

  /**
   * Gets hash length in ints
   * 
   * @return   short:   hash length in ints
   */ 
    public short GetULHashLength() {
          
        return Sha384.HASHULS;
    }

  /**
   * Gets hash length in longs (64 bits)
   * 
   * @return   short:   hash length in longs
   */ 
    public short Get64HashLength() {
          
        return Sha384.HASH64S;
    }

  /**
   * Gets the type of the object
   * 
   * @return    Hashes:     Sha 384 enumerator name
   */ 
    public Hashes GetType() {
          
        return Sha384.HASHNAME;
    }

}
