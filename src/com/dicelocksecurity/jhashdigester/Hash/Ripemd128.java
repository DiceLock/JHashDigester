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
  * Ripemd 128 hash algorithm implementation
  * 
  * @author      Angel Ferré @ DiceLock Security
  * @version     5.0.0.1
  * @since       2011-10-04
  */
public class Ripemd128 extends BaseRipemd128X {

  /**
   * Hash Algorithms Class enumerator name
   */ 
    protected static final Hashes HASHNAME = Hashes.RIPEMD_128;

  /**
   * Number of hash bits
   */ 
    protected static final short HASHBITS = 128;
  /**
   * Number of hash unsigned chars
   */ 
    protected static final short HASHUCS = 16;
  /**
   * Number of hash unsigned short ints
   */ 
    protected static final short HASHUSS = 8;
  /**
   * Number of hash unsigned long ints
   */ 
    protected static final short HASHULS = 4;

  /**
   * Computes the 128 byte stream of information  
   * 
   * @param     stream     portion of bit stream to be added to compute the hash
   */ 
    protected void Compress(int[] stream) {
        BaseHash_Int a1 = new BaseHash_Int();
        BaseHash_Int a2 = new BaseHash_Int();
        BaseHash_Int b1 = new BaseHash_Int();
        BaseHash_Int b2 = new BaseHash_Int();
        BaseHash_Int c1 = new BaseHash_Int();
        BaseHash_Int c2 = new BaseHash_Int();
        BaseHash_Int d1 = new BaseHash_Int();
        BaseHash_Int d2 = new BaseHash_Int();
    
        a1.setValue(this.messageDigest.GetULPosition(0));
        a2.setValue(this.messageDigest.GetULPosition(0));
        b1.setValue(this.messageDigest.GetULPosition(1));
        b2.setValue(this.messageDigest.GetULPosition(1));
        c1.setValue(this.messageDigest.GetULPosition(2)); 
        c2.setValue(this.messageDigest.GetULPosition(2));
        d1.setValue(this.messageDigest.GetULPosition(3)); 
        d2.setValue(this.messageDigest.GetULPosition(3));

        Transform_F0(a1, b1, c1, d1, stream);
        Transform_G1(a1, b1, c1, d1, stream);
        Transform_H2(a1, b1, c1, d1, stream);
        Transform_I3(a1, b1, c1, d1, stream);
        Transform_I5(a2, b2, c2, d2, stream);
        Transform_H6(a2, b2, c2, d2, stream);
        Transform_G7(a2, b2, c2, d2, stream);
        Transform_F9(a2, b2, c2, d2, stream);
        d2.setValue(d2.getValue() + c1.getValue() + this.messageDigest.GetULPosition(1));
        this.messageDigest.SetULPosition(1, this.messageDigest.GetULPosition(2) + d1.getValue() + a2.getValue());
        this.messageDigest.SetULPosition(2, this.messageDigest.GetULPosition(3) + a1.getValue() + b2.getValue());
        this.messageDigest.SetULPosition(3, this.messageDigest.GetULPosition(0) + b1.getValue() + c2.getValue());
        this.messageDigest.SetULPosition(0, d2.getValue());
    }

  /**
   * Constructor, default 
   */ 
    public Ripemd128() {
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
   * Gets hash length in bits
   * 
   * @return   short:   hash length in bits   
   */ 
    public short GetBitHashLength() {
                                              
        return Ripemd128.HASHBITS;
    }

  /**
   * Gets hash length in bytes
   * 
   * @return   short:   hash length in bytes   
   */ 
    public short GetUCHashLength() {
                                              
        return Ripemd128.HASHUCS;
    }

  /**
   * Gets hash length in shorts 
   * 
   * @return   short:   hash length in shorts   
   */ 
    public short GetUSHashLength() {
                                              
        return Ripemd128.HASHUSS;
    }

  /**
   * Gets hash length in ints
   * 
   * @return   short:   hash length in ints
   */ 
    public short GetULHashLength() {
                                              
        return Ripemd128.HASHULS;
    }

  /**
   * Gets the type of the object
   * 
   * @return    Hashes:     Ripemd 128 enumerator name
   */ 
    public Hashes GetType() {
                                              
        return Ripemd128.HASHNAME;
    }

}
