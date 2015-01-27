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
  * Ripemd 256 hash algorithm implementation
  * 
  * @author      Angel Ferré @ DiceLock Security
  * @version     5.0.0.1
  * @since       2011-10-04
  */
public class Ripemd256 extends BaseRipemd128X {

  /**
   * Hash Algorithms Class enumerator name
   */
    protected static final Hashes HASHNAME = Hashes.RIPEMD_256;

  /**
   * Number of hash bits
   */
    protected static final short HASHBITS = 256;
  /**
   * Number of hash unsigned chars
   */
    protected static final short HASHUCS = 32;
  /**
   * Number of hash unsigned short ints
   */
    protected static final short HASHUSS = 16;
  /**
   * Number of hash unsigned long ints
   */
    protected static final short HASHULS = 8;

  /**
   * Initial states of Ripemd 256 algorithm
   */
    private static final int INISTATE4 = 0x76543210;
    private static final int INISTATE5 = 0xFEDCBA98;
    private static final int INISTATE6 = 0x89ABCDEF;
    private static final int INISTATE7 = 0x01234567;

  /**
   * Computes the 256 byte stream of information  
   * 
   * @param     stream     portion of bit stream to be added to compute the hash
   */ 
    protected void Compress(int[] stream) {
        BaseHash_Int a1 = new BaseHash_Int();
        BaseHash_Int b1 = new BaseHash_Int();
        BaseHash_Int c1 = new BaseHash_Int();
        BaseHash_Int d1 = new BaseHash_Int();
        BaseHash_Int a2 = new BaseHash_Int();
        BaseHash_Int b2 = new BaseHash_Int();
        BaseHash_Int c2 = new BaseHash_Int();
        BaseHash_Int d2 = new BaseHash_Int();
        BaseHash_Int temp = new BaseHash_Int();

        a1.setValue(this.messageDigest.GetULPosition(0));
        b1.setValue(this.messageDigest.GetULPosition(1)); 
        c1.setValue(this.messageDigest.GetULPosition(2)); 
        d1.setValue(this.messageDigest.GetULPosition(3)); 
        a2.setValue(this.messageDigest.GetULPosition(4));
        b2.setValue(this.messageDigest.GetULPosition(5));
        c2.setValue(this.messageDigest.GetULPosition(6));
        d2.setValue(this.messageDigest.GetULPosition(7));
      
        Transform_F0(a1, b1, c1, d1, stream);
        Transform_I5(a2, b2, c2, d2, stream);
        temp.setValue(a1.getValue());
        a1.setValue(a2.getValue());
        a2.setValue(temp.getValue());
        Transform_G1(a1, b1, c1, d1, stream);
        Transform_H6(a2, b2, c2, d2, stream);
        temp.setValue(b1.getValue());
        b1.setValue(b2.getValue());
        b2.setValue(temp.getValue());
        Transform_H2(a1, b1, c1, d1, stream);
        Transform_G7(a2, b2, c2, d2, stream);
        temp.setValue(c1.getValue());
        c1.setValue(c2.getValue());
        c2.setValue(temp.getValue());
        Transform_I3(a1, b1, c1, d1, stream);
        Transform_F9(a2, b2, c2, d2, stream);
        temp.setValue(d1.getValue());
        d1.setValue(d2.getValue());
        d2.setValue(temp.getValue());
        this.messageDigest.SetULPosition(0, this.messageDigest.GetULPosition(0) + a1.getValue());
        this.messageDigest.SetULPosition(1, this.messageDigest.GetULPosition(1) + b1.getValue());
        this.messageDigest.SetULPosition(2, this.messageDigest.GetULPosition(2) + c1.getValue());
        this.messageDigest.SetULPosition(3, this.messageDigest.GetULPosition(3) + d1.getValue());
        this.messageDigest.SetULPosition(4, this.messageDigest.GetULPosition(4) + a2.getValue());
        this.messageDigest.SetULPosition(5, this.messageDigest.GetULPosition(5) + b2.getValue());
        this.messageDigest.SetULPosition(6, this.messageDigest.GetULPosition(6) + c2.getValue());
        this.messageDigest.SetULPosition(7, this.messageDigest.GetULPosition(7) + d2.getValue());
    }

  /**
   * Constructor, default 
   */ 
    public Ripemd256() {
        super();
    }

  /**
   * Destructor
   */ 
    public void finalize() {
                                              
    }

  /**
   * Initializes state of Ripmed 256 algorithm
   */ 
    public void Initialize() {
                                              
        super.Initialize();
        this.messageDigest.SetULPosition(4, Ripemd256.INISTATE4);
        this.messageDigest.SetULPosition(5, Ripemd256.INISTATE5);
        this.messageDigest.SetULPosition(6, Ripemd256.INISTATE6);
        this.messageDigest.SetULPosition(7, Ripemd256.INISTATE7);
    }

  /**
   * Gets hash length in bits
   * 
   * @return   short:   hash length in bits   
   */ 
    public short GetBitHashLength() {
                                              
        return Ripemd256.HASHBITS;
    }

 /**
  * Gets hash length in bytes
  * 
  * @return   short:   hash length in bytes   
  */ 
    public short GetUCHashLength() {
                                              
        return Ripemd256.HASHUCS;
    }

  /**
   * Gets hash length in shorts 
   * 
   * @return   short:   hash length in shorts   
   */ 
    public short GetUSHashLength() {
                                              
        return Ripemd256.HASHUSS;
    }

  /**
   * Gets hash length in ints
   * 
   * @return   short:   hash length in ints
   */ 
    public short GetULHashLength() {
                                              
        return Ripemd256.HASHULS;
    }

  /**
   * Gets the type of the object
   * 
   * @return    Hashes:     Ripemd 256 enumerator name
   */ 
    public Hashes GetType() {
                                              
        return Ripemd256.HASHNAME;
    }

}
