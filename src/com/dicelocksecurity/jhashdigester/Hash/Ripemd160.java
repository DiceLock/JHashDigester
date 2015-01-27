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
  * Ripemd 160 hash algorithm implementation
  * 
  * @author      Angel Ferré @ DiceLock Security
  * @version     5.0.0.1
  * @since       2011-10-04
  */
public class Ripemd160 extends BaseRipemd160X {

  /**
   * Hash Algorithms Class enumerator name
   */
    protected static final Hashes HASHNAME = Hashes.RIPEMD_160;

  /**
   * Number of hash bits
   */
    protected static final short HASHBITS = 160;
  /**
   * Number of hash unsigned chars
   */
    protected static final short HASHUCS = 20;
  /**
   * Number of hash unsigned short ints
   */
    protected static final short HASHUSS = 10;
  /**
   * Number of hash unsigned long ints
   */
    protected static final short HASHULS = 5;

  /**
   * Computes the 160 byte stream of information  
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
        BaseHash_Int e1 = new BaseHash_Int();
        BaseHash_Int e2 = new BaseHash_Int();
        int temp;

        a1.setValue(this.messageDigest.GetULPosition(0));
        a2.setValue(this.messageDigest.GetULPosition(0));
        b1.setValue(this.messageDigest.GetULPosition(1));
        b2.setValue(this.messageDigest.GetULPosition(1));
        c1.setValue(this.messageDigest.GetULPosition(2)); 
        c2.setValue(this.messageDigest.GetULPosition(2));
        d1.setValue(this.messageDigest.GetULPosition(3)); 
        d2.setValue(this.messageDigest.GetULPosition(3));
        e1.setValue(this.messageDigest.GetULPosition(4)); 
        e2.setValue(this.messageDigest.GetULPosition(4));

        this.Transform_F0(a1, b1, c1, d1, e1, stream);
        this.Transform_G1(a1, b1, c1, d1, e1, stream);
        this.Transform_H2(a1, b1, c1, d1, e1, stream);
        this.Transform_I3(a1, b1, c1, d1, e1, stream);
        this.Transform_J4(a1, b1, c1, d1, e1, stream);
        this.Transform_J5(a2, b2, c2, d2, e2, stream);
        this.Transform_I6(a2, b2, c2, d2, e2, stream);
        this.Transform_H7(a2, b2, c2, d2, e2, stream);
        this.Transform_G8(a2, b2, c2, d2, e2, stream);
        this.Transform_F9(a2, b2, c2, d2, e2, stream);
        temp = this.messageDigest.GetULPosition(1) + d2.getValue() +c1.getValue();
        
        this.messageDigest.SetULPosition(1, this.messageDigest.GetULPosition(2) + e2.getValue() + d1.getValue());
        this.messageDigest.SetULPosition(2, this.messageDigest.GetULPosition(3) + a2.getValue() + e1.getValue());
        this.messageDigest.SetULPosition(3, this.messageDigest.GetULPosition(4) + b2.getValue() + a1.getValue());
        this.messageDigest.SetULPosition(4, this.messageDigest.GetULPosition(0) + c2.getValue() + b1.getValue());
        this.messageDigest.SetULPosition(0, temp);
    }

  /**
   * Constructor, default 
   */ 
    public Ripemd160() {
        super();
    }

  /**
   * Destructor
   */ 
    public void finalize() {
                                              
    }

  /**
   * Gets hash length in bits
   * 
   * @return   short:   hash length in bits   
   */ 
    public short GetBitHashLength() {
                                              
        return Ripemd160.HASHBITS;
    }

 /**
  * Gets hash length in bytes
  * 
  * @return   short:   hash length in bytes   
  */ 
    public short GetUCHashLength() {
                                              
        return Ripemd160.HASHUCS;
    }

  /**
   * Gets hash length in shorts 
   * 
   * @return   short:   hash length in shorts   
   */ 
    public short GetUSHashLength() {
                                              
        return Ripemd160.HASHUSS;
    }

  /**
   * Gets hash length in ints
   * 
   * @return   short:   hash length in ints
   */ 
    public short GetULHashLength() {
                                              
        return Ripemd160.HASHULS;
    }

  /**
   * Gets the type of the object
   * 
   * @return    Hashes:     Ripemd 160 enumerator name
   */ 
    public Hashes GetType() {
                                              
        return Ripemd160.HASHNAME;
    }

}
