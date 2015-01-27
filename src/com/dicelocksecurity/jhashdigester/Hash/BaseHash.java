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
  * Base hash algorithm class 
  * 
  * @author      Angel Ferré @ DiceLock Security
  * @version     5.0.0.1
  * @since       2011-10-03
  */
public abstract class BaseHash {

  /**
   * Pointer to BaseCryptoRandomStream digest
   */
    protected BaseCryptoRandomStream messageDigest;

  /**
   * Constructor, default
   */
    public BaseHash() {
        super();
    }

  /**
   * Constructor assigning diggest BaseCryptoRandomStream
   * 
   * @param    stream     BaseCryptoRandomStream hash algorithm digest stream
   */
    public BaseHash(BaseCryptoRandomStream stream) {

        this.messageDigest = stream;
        for (int i = 0; i < stream.GetUCLength(); i++) {
            stream.SetUCPosition(i, (byte)0x00);
        }
    }

  /**
   * Destructor
   */
    public void finalize() {

        this.messageDigest = null;
    }

  /**
   * Set the Message Digest BaseCryptoRandomStream
   * 
   * @param    stream     BaseCryptoRandomStream hash algorithm digest stream
   */
    public void SetMessageDigest(BaseCryptoRandomStream stream) {

        this.messageDigest = stream;
        for (int i = 0; i < stream.GetUCLength(); i++) {
          stream.SetUCPosition(i, (byte)0x00);
        }
    }

  /**
   * Initialize BaseHash
   */
    abstract public void Initialize();

  /**
   * Adds the BaseCryptoRandomStream
   * 
   * @param     stream    bit stream to be added to the hash
   */
    abstract public void Add(BaseCryptoRandomStream stream);

  /**
   * Finalize the hash
   */
    abstract public void Finalize();

  /**
   * Gets the hash
   * 
   * @return    BaseCryptoRandomStream    gets BaseCryptoRandomStream hash digest stream
   */
    public BaseCryptoRandomStream GetMessageDigest() {

        return this.messageDigest;
    }

  /**
   * Gets hash length in bits
   * 
   * @return   short:   hash length in bits   
   */
    abstract public short GetBitHashLength();

  /**
   * Gets hash length in bytes
   * 
   * @return   short:   hash length in bytes   
   */
    abstract public short GetUCHashLength();

  /**
   * Gets hash length in shorts 
   * 
   * @return   short:   hash length in shorts   
   */
    abstract public short GetUSHashLength();

  /**
   * Gets hash length in ints
   * 
   * @return   short:   hash length in ints
   */
    abstract public short GetULHashLength();

  /**
   * Gets the number of bits in the hash block to be hashed
   * 
   * @return    short:    number of bits in the hash block to be hashed
   */
    abstract public short GetBitHashBlockLength();

  /**
   * Gets the number of bytes in the hash block to be hashed
   * 
   * @return    short:    number of bytes in the hash block to be hashed
   */
    abstract public short GetUCHashBlockLength();

  /**
   * Gets the number of shorts in the hash block to be hashed
   * 
   * @return    short:    number of shorts in the hash block to be hashed
   */
    abstract public short GetUSHashBlockLength();

  /**
   * Gets the number of ints in the hash block to be hashed
   * 
   * @return    short:    number of ints in the hash block to be hashed
   */
    abstract public short GetULHashBlockLength();

  /**
   * Gets the type of the object
   * 
   * @return    Hashes:     Sha 512 enumerator name
   */
    abstract public Hashes GetType();

}
