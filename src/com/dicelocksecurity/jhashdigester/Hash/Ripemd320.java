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
  * Ripemd 320 hash algorithm implementation
  * 
  * @author      Angel Ferré @ DiceLock Security
  * @version     5.0.0.1
  * @since       2011-10-04
  */
public class Ripemd320 extends BaseRipemd160X {

  /**
   * Hash Algorithms Class enumerator name
   */
    protected static final Hashes HASHNAME = Hashes.RIPEMD_320;

  /**
   * Number of hash bits
   */
    protected static final short HASHBITS = 320;
  /**
   * Number of hash unsigned chars
   */
    protected static final short HASHUCS = 40;
  /**
   * Number of hash unsigned short ints
   */
    protected static final short HASHUSS = 20;
  /**
   * Number of hash unsigned long ints
   */
    protected static final short HASHULS = 10;

  /**
   * Initial states of Ripemd 320 algorithm
   */
    private static final int INISTATE5 = 0x76543210;
    private static final int INISTATE6 = 0xFEDCBA98;
    private static final int INISTATE7 = 0x89ABCDEF;
    private static final int INISTATE8 = 0x01234567;
    private static final int INISTATE9 = 0x3C2D1E0F;

  /**
   * Computes the 320 byte stream of information  
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
        b1.setValue(this.messageDigest.GetULPosition(1)); 
        c1.setValue(this.messageDigest.GetULPosition(2)); 
        d1.setValue(this.messageDigest.GetULPosition(3)); 
        e1.setValue(this.messageDigest.GetULPosition(4)); 
        a2.setValue(this.messageDigest.GetULPosition(5));
        b2.setValue(this.messageDigest.GetULPosition(6));
        c2.setValue(this.messageDigest.GetULPosition(7));
        d2.setValue(this.messageDigest.GetULPosition(8));
        e2.setValue(this.messageDigest.GetULPosition(9)); 

        this.Transform_F0(a1, b1, c1, d1, e1, stream);
        this.Transform_J5(a2, b2, c2, d2, e2, stream);
        temp = a1.getValue();
        a1.setValue(a2.getValue());
        a2.setValue(temp);
        this.Transform_G1(a1, b1, c1, d1, e1, stream);
        this.Transform_I6(a2, b2, c2, d2, e2, stream);
        temp = b1.getValue();
        b1.setValue(b2.getValue());
        b2.setValue(temp);
        this.Transform_H2(a1, b1, c1, d1, e1, stream);
        this.Transform_H7(a2, b2, c2, d2, e2, stream);
        temp = c1.getValue();
        c1.setValue(c2.getValue());
        c2.setValue(temp);
        this.Transform_I3(a1, b1, c1, d1, e1, stream);
        this.Transform_G8(a2, b2, c2, d2, e2, stream);
        temp = d1.getValue();
        d1.setValue(d2.getValue());
        d2.setValue(temp);
        this.Transform_J4(a1, b1, c1, d1, e1, stream);
        this.Transform_F9(a2, b2, c2, d2, e2, stream);
        temp = e1.getValue();
        e1.setValue(e2.getValue());
        e2.setValue(temp);
        this.messageDigest.SetULPosition(0, this.messageDigest.GetULPosition(0) + a1.getValue());
        this.messageDigest.SetULPosition(1, this.messageDigest.GetULPosition(1) + b1.getValue());
        this.messageDigest.SetULPosition(2, this.messageDigest.GetULPosition(2) + c1.getValue());
        this.messageDigest.SetULPosition(3, this.messageDigest.GetULPosition(3) + d1.getValue());
        this.messageDigest.SetULPosition(4, this.messageDigest.GetULPosition(4) + e1.getValue());
        this.messageDigest.SetULPosition(5, this.messageDigest.GetULPosition(5) + a2.getValue());
        this.messageDigest.SetULPosition(6, this.messageDigest.GetULPosition(6) + b2.getValue());
        this.messageDigest.SetULPosition(7, this.messageDigest.GetULPosition(7) + c2.getValue());
        this.messageDigest.SetULPosition(8, this.messageDigest.GetULPosition(8) + d2.getValue());
        this.messageDigest.SetULPosition(9, this.messageDigest.GetULPosition(9) + e2.getValue());
    }

  /**
   * Constructor, default 
   */ 
    public Ripemd320() {
        super();
    }

  /**
   * Destructor
   */ 
    public void finalize() {
      
    }

  /**
   * Initializes state of Ripmed 320 algorithm
   */ 
    public void Initialize() {
      
        super.Initialize();
        this.messageDigest.SetULPosition(5, Ripemd320.INISTATE5);
        this.messageDigest.SetULPosition(6, Ripemd320.INISTATE6);
        this.messageDigest.SetULPosition(7, Ripemd320.INISTATE7);
        this.messageDigest.SetULPosition(8, Ripemd320.INISTATE8);
        this.messageDigest.SetULPosition(9, Ripemd320.INISTATE9);
    }

  /**
   * Gets hash length in bits
   * 
   * @return   short:   hash length in bits   
   */ 
    public short GetBitHashLength() {
      
        return Ripemd320.HASHBITS; 
    }

  /**
   * Gets hash length in bytes
   * 
   * @return   short:   hash length in bytes   
   */ 
    public short GetUCHashLength() {
      
        return Ripemd320.HASHUCS; 
    }

  /**
   * Gets hash length in shorts 
   * 
   * @return   short:   hash length in shorts   
   */ 
    public short GetUSHashLength() {
      
        return Ripemd320.HASHUSS; 
    }

  /**
   * Gets hash length in ints
   * 
   * @return   short:   hash length in ints
   */ 
    public short GetULHashLength() {
      
        return Ripemd320.HASHULS; 
    }

  /**
   * Gets the type of the object
   * 
   * @return    Hashes:     Ripemd 320 enumerator name
   */ 
    public Hashes GetType() {
     
        return Ripemd320.HASHNAME; 
    }
}
