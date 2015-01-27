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
  * Base class for Sha 1, Sha 224 and Sha 256 hash algorithms 
  * 
  * @author      Angel Ferré @ DiceLock Security
  * @version     5.0.0.1
  * @since       2011-10-03
  */
public abstract class BaseSha32 extends BaseHash {

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
   * Equation modulo constant value
   */
    protected static final int EQUATIONMODULO = 448;

  /**
   * Array to store remaining bytes of intermediate hash operation
   */
    protected byte[] remainingBytes = new byte[BaseSha32.HASHBLOCKUCS];
    protected int remainingBytesLength;

  /**
   * Total processed message length in bytes
   */
    protected long messageBitLengthHigh;
    protected long messageBitLengthLow;

  /**
   * Adds messaage length processed, if it is greater than unsigned long makes use
   * of another usigned long to store overflow
   * 
   * @param     byteLength    number of stream bytes added to compute the hash 
   */
    protected void AddMessageLength(long byteLength) {

        if ((this.messageBitLengthLow + (byteLength * TypeSizes.BYTE_BITS)) <
            this.messageBitLengthLow)
            // add overflow of unsigned long
            this.messageBitLengthHigh++;
        this.messageBitLengthLow += (byteLength * TypeSizes.BYTE_BITS);
    }

  /**
   * Computes the chunk block of information
   * 
   * @param     stream     portion of bit stream to be added to ciompute the hash
   */
    abstract protected void Compress(BaseCryptoRandomStream digest, byte[] stream);

  /**
   * Constructor, default
   */
    public BaseSha32() {
        super();

        this.remainingBytesLength = 0;
        this.messageBitLengthHigh = 0;
        this.messageBitLengthLow = 0;
    }

  /**
   * Destructor
   */
    public void finalize() {

        this.remainingBytesLength = 0;
        this.messageBitLengthHigh = 0;
        this.messageBitLengthLow = 0;
    }

  /**
   * Adds the BaseCryptoRandomStream to the hash
   * 
   * @param     stream    bit stream that is added to produce the hash
   */
    public void Add(BaseCryptoRandomStream stream) {
        int startStreamByte = 0, processBytes = 0;
        int numBytes = 0;
        int i;
        byte[] subArray;

        // If bytes left from previous added stream, then they will be processed now with added data from new stream
        if (this.remainingBytesLength != 0) {
            if ((this.remainingBytesLength + stream.GetUCLength()) >
                ((int)this.GetUCHashBlockLength() - 1)) {
                // Setting the point to start the current stream processed
                startStreamByte =
                        this.GetUCHashBlockLength() - this.remainingBytesLength;
                processBytes =
                        stream.GetUCLength() - (this.GetUCHashBlockLength() -
                                                this.remainingBytesLength);

                for (i = 0;
                     i < (this.GetUCHashBlockLength() - this.remainingBytesLength);
                     i++) {
                    this.remainingBytes[this.remainingBytesLength + i] =
                            stream.GetUCPosition(i);
                }
                // Process remaining bytes of previous streams and 64 byte padding of current stream
                this.Compress(this.messageDigest, this.remainingBytes);
                // Updating message byt length processed
                this.AddMessageLength(this.GetUCHashBlockLength());
                // Remaining bytes of previous strema set to 0
                this.remainingBytesLength = 0;
            } else {
                processBytes = stream.GetUCLength();
            }
        } else {
            processBytes = stream.GetUCLength();
            startStreamByte = 0;
        }

        for (numBytes = 0;
             processBytes > ((int)this.GetUCHashBlockLength() - 1);
             numBytes += this.GetUCHashBlockLength()) {
            // Process the chunk
            subArray =
                    new byte[stream.GetUCLength() - startStreamByte - numBytes];
            for (i = 0; i < subArray.length; i++) {
                subArray[i] = stream.GetUCPosition(startStreamByte + numBytes + i);
            }
            this.Compress(this.messageDigest, subArray);
            // Updating message byt length processed
            this.AddMessageLength(this.GetUCHashBlockLength());
            processBytes -= this.GetUCHashBlockLength();
        }

        // If remaining bytes left, they will be copied for the next added stream
        if (processBytes > 0) {

            for (i = 0; i < processBytes; i++) {
                this.remainingBytes[this.remainingBytesLength + i] =
                        stream.GetUCPosition(stream.GetUCLength() -
                                             processBytes + i);
            }
            this.remainingBytesLength += processBytes;
        }
    }

  /**
   * Finalize the hash
   */
    public void Finalize() {
        int i;

        this.remainingBytes[this.remainingBytesLength] = (byte)0x80;
        if ((this.remainingBytesLength * TypeSizes.BYTE_BITS) % BaseSha32.HASHBLOCKBITS >=
            BaseSha32.EQUATIONMODULO) {
            for (i = (this.remainingBytesLength + 1);
                 i < (this.GetUCHashBlockLength() - this.remainingBytesLength -
                      1); i++) {
                this.remainingBytes[i] = 0;
            }
            this.Compress(this.messageDigest, this.remainingBytes);
            this.AddMessageLength(this.remainingBytesLength);
            for (i = 0; i < this.GetUCHashBlockLength(); i++) {
                this.remainingBytes[i] = 0;
            }
            this.remainingBytesLength = 0;
        } else {
            for (i = (this.remainingBytesLength + 1);
                 i < (this.GetUCHashBlockLength() - this.remainingBytesLength -
                      1); i++) {
                this.remainingBytes[i] = 0;
            }
        }
        this.AddMessageLength(this.remainingBytesLength);
        this.remainingBytes[56] =
                (byte)((this.messageBitLengthHigh >>> 24) & 255);
        this.remainingBytes[57] =
                (byte)((this.messageBitLengthHigh >>> 16) & 255);
        this.remainingBytes[58] =
                (byte)((this.messageBitLengthHigh >>> 8) & 255);
        this.remainingBytes[59] = (byte)((this.messageBitLengthHigh) & 255);
        this.remainingBytes[60] =
                (byte)((this.messageBitLengthLow >>> 24) & 255);
        this.remainingBytes[61] =
                (byte)((this.messageBitLengthLow >>> 16) & 255);
        this.remainingBytes[62] =
                (byte)((this.messageBitLengthLow >>> 8) & 255);
        this.remainingBytes[63] = (byte)((this.messageBitLengthLow) & 255);
        this.Compress(this.messageDigest, this.remainingBytes);
    }

  /**
   * Gets the number of bits in the hash block to be hashed
   * 
   * @return    short:    number of bits in the hash block to be hashed
   */
    public short GetBitHashBlockLength() {

        return BaseSha32.HASHBLOCKBITS;
    }

  /**
   * Gets the number of unsigned chars in the hash block to be hashed
   * 
   * @return    short:    number of bytes in the hash block to be hashed
   */
    public short GetUCHashBlockLength() {

        return BaseSha32.HASHBLOCKUCS;
    }

  /**
   * Gets the number of unsigned short ints in the hash block to be hashed
   * 
   * @return    short:    number of shorts in the hash block to be hashed
   */
    public short GetUSHashBlockLength() {

        return BaseSha32.HASHBLOCKUSS;
    }

  /**
   * Gets the number of unsigned long ints in the hash block to be hashed
   * 
   * @return    short:    number of ints in the hash block to be hashed
   */
    public short GetULHashBlockLength() {

        return BaseSha32.HASHBLOCKULS;
    }
  
}
