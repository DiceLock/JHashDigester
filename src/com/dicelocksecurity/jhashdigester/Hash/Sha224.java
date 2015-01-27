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
  * Sha 224 hash algorithm implementation
  * 
  * @author      Angel Ferré @ DiceLock Security
  * @version     5.0.0.1
  * @since       2011-10-05
  */
public class Sha224 extends Sha256 {

  /**
   * Hash Algorithms Class enumerator name
   */
    private static final Hashes HASHNAME = Hashes.SHA_224;

  /**
   * Number of hash bits
   */
    private static final short HASHBITS = 224;
  /**
   * Number of hash bytes
   */
    private static final short HASHUCS = 28;
  /**
   * Number of hash shorts
   */
    private static final short HASHUSS = 14;
  /**
   * Number of hash ints
   */
    private static final short HASHULS = 7;

  /**
   * Initial hash values of SHA256 
   */
    private static final int[] INITIALS = {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4};

  /**
   * Pointer to BaseCryptoRandomStream digest for SHA 256 hash algorithm
   */
    private BaseCryptoRandomStream workingDigest256; 
    
  /**
   * Boolean pointing if meesaageDigest for SHA 256 has been created automatically
   */
    private boolean autoWorkingDigest;
    
  /**
   * Constructor, default 
   */ 
    public Sha224() {
        super();

        this.workingDigest256 = null;
        this.autoWorkingDigest = false;
    }

  /**
   * Destructor
   */
    public void finalize() {
      
        if ( autoWorkingDigest ) {
          this.workingDigest256 = null;
          this.autoWorkingDigest = false;
        }
    }

  /**
   * Set the Working Digest  BaseCryptoRandomStream for underlying SHA256 algorithm
   * 
   * @param   workDigest      BaseCryptoRandomStream working digest to compute underlying Sha 256 hash algorithm
   */
    public void SetWorkingDigest(BaseCryptoRandomStream workDigest) {
  
        this.workingDigest256 = workDigest;
    }

  /**
   * Get the Working Digest  BaseCryptoRandomStream for underlying SHA256 algorithm length in bits
   * 
   * @return    short:    underlying Sha 256 digest length in bits
   */
    public short GetWorkingDigestBitLength() {
  
        return super.GetBitHashLength();
    }

  /**
   * Get the Working Digest  BaseCryptoRandomStream for underlying SHA256 algorithm length in bytes
   * 
   * @return    short:    underlying Sha 256 digest length in bytes
   */
    public short GetWorkingDigestUCLength() {
  
        return super.GetUCHashLength();
    }

  /**
   * Get the Working Digest  BaseCryptoRandomStream for underlying SHA256 algorithm length in shorts
   * 
   * @return    short:    underlying Sha 256 digest length in shorts
   */
    public short GetWorkingDigestUSLength() {
  
        return super.GetUSHashLength();
    }

  /**
   * Get the Working Digest  BaseCryptoRandomStream for underlying SHA256 algorithm length in ints
   * 
   * @return    short:    underlying Sha 256 digest length in ints
   */
    public short GetWorkingDigestULLength() {
  
        return super.GetULHashLength();
    }

  /**
   * Initializes common states of Sha224 algorithm
   */
    public void Initialize() {
  
        if (this.workingDigest256 == null) {
          this.workingDigest256 = new DefaultCryptoRandomStream();
          this.workingDigest256.SetCryptoRandomStreamUC(this.GetWorkingDigestUCLength());
          this.autoWorkingDigest = true;
        }
        this.workingDigest256.SetULPosition(0, Sha224.INITIALS[0]);
        this.workingDigest256.SetULPosition(1, Sha224.INITIALS[1]);
        this.workingDigest256.SetULPosition(2, Sha224.INITIALS[2]);
        this.workingDigest256.SetULPosition(3, Sha224.INITIALS[3]);
        this.workingDigest256.SetULPosition(4, Sha224.INITIALS[4]);
        this.workingDigest256.SetULPosition(5, Sha224.INITIALS[5]);
        this.workingDigest256.SetULPosition(6, Sha224.INITIALS[6]);
        this.workingDigest256.SetULPosition(7, Sha224.INITIALS[7]);
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
            // Process remaining bytes of previous streams and 64 byte padding of current stream
            this.Compress(this.workingDigest256, this.remainingBytes);
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
          this.Compress(this.workingDigest256, subArray);
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
        for (i = 0; i < this.GetULHashLength(); i++) {
          this.messageDigest.SetULPosition(i, this.workingDigest256.GetULPosition(i));
        }
    }

  /**
   * Finalizes hash 
   */
    public void Finalize() {
        int i;

        this.remainingBytes[this.remainingBytesLength] = (byte)0x80;
        if ((this.remainingBytesLength * TypeSizes.BYTE_BITS) % BaseSha32.HASHBLOCKBITS >= BaseSha32.EQUATIONMODULO) {
          for (i = 0; i < (this.GetUCHashBlockLength() - this.remainingBytesLength -1); i++) {
            this.remainingBytes[this.remainingBytesLength + 1 + i] = 0;
          }
          this.Compress(this.workingDigest256, this.remainingBytes);
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
        this.remainingBytes[56] = (byte)((this.messageBitLengthHigh >>> 24) & 255);
        this.remainingBytes[57] = (byte)((this.messageBitLengthHigh >>> 16) & 255);
        this.remainingBytes[58] = (byte)((this.messageBitLengthHigh >>> 8) & 255);
        this.remainingBytes[59] = (byte)((this.messageBitLengthHigh) & 255);
        this.remainingBytes[60] = (byte)((this.messageBitLengthLow >>> 24) & 255);
        this.remainingBytes[61] = (byte)((this.messageBitLengthLow >>> 16) & 255);
        this.remainingBytes[62] = (byte)((this.messageBitLengthLow >>> 8) & 255);
        this.remainingBytes[63] = (byte)((this.messageBitLengthLow) & 255);
        this.Compress(this.workingDigest256, this.remainingBytes);
        for (i = 0; i < this.GetULHashLength(); i++) {
          this.messageDigest.SetULPosition(i, this.workingDigest256.GetULPosition(i));
        }
    }

  /**
   * Gets hash length in bits
   * 
   * @return   short:   hash length in bits   
   */ 
    public short GetBitHashLength() {
  
        return Sha224.HASHBITS;
    }

  /**
   * Gets hash length in bytes
   * 
   * @return   short:   hash length in bytes   
   */ 
    public short GetUCHashLength() {
  
        return Sha224.HASHUCS;
    }

  /**
   * Gets hash length in shorts 
   * 
   * @return   short:   hash length in shorts   
   */ 
    public short GetUSHashLength() {
  
        return Sha224.HASHUSS;
    }

  /**
   * Gets hash length in ints
   * 
   * @return   short:   hash length in ints
   */ 
    public short GetULHashLength() {
  
        return Sha224.HASHULS;
    }

  /**
   * Gets the type of the object
   * 
   * @return    Hashes:     Sha 224 enumerator name
   */ 
    public Hashes GetType() {
  
        return Sha224.HASHNAME;
    }
  
}
