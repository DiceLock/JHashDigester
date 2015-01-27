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
  * Ripemd160X base class for Ripemd160 and Ripemd320 hash algorithms
  * 
  * @author      Angel Ferré @ DiceLock Security
  * @version     5.0.0.1
  * @since       2011-10-03
  */
public abstract class BaseRipemd160X extends BaseRipemd {
    
  /**
   * Special F function object
   */
    protected static final BaseRipemd_Function_F functionF = new BaseRipemd_Function_F();
  /**
   * Special G function object
   */
    protected static final BaseRipemd_Function_G functionG = new BaseRipemd_Function_G();
  /**
   * Special H function object
   */
    protected static final BaseRipemd_Function_H functionH = new BaseRipemd_Function_H();
  /**
   * Special I function object
   */
    protected static final BaseRipemd_Function_I functionI = new BaseRipemd_Function_I();
  /**
   * Special J function object
   */
    protected static final BaseRipemd_Function_J functionJ = new BaseRipemd_Function_J();

    
  /**
   * CONSTANTs for 160 and 320 RIPEMD algorithms 
   */
    protected static final int CONSTANT4 = 0xA953FD4E;
    protected static final int CONSTANT8 = 0x7A6D76E9;

  /**
   * Amounts of rotate left
   */
    protected static final short RL_64_79[] = {9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};
  /**
   * Amounts of prime rotate left 
   */
    protected static final short PRIME_RL_64_79[] = {8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};

  /**
   * Initial states of Ripemd 160 and 320 algorithms
   */
    protected static final int INISTATE4 = 0xC3D2E1F0;

  /**
   * Ripemd128X transform function
   * 
   * @param   function    special function
   * @param   a           int parameter by reference to be operated upon
   * @param   b           int parameter by reference to operate with
   * @param   c           int parameter by reference to operate with
   * @param   d           int parameter by reference to operate with
   * @param   e           int parameter by reference to operate with
   * @param   x           int parameter to operate with
   * @param   s           int parameter of rotation to operate with
   * @param   k           int parameter CONSTANT to operate with
   */
    private void Ripemd_Transform160X(BaseRipemd_BaseFunctions function, BaseHash_Int a, BaseHash_Int b, BaseHash_Int c, BaseHash_Int d, BaseHash_Int e, int x, int s, int k) {
    
        a.setValue(a.getValue() + function.Execute(b.getValue(), c.getValue(), d.getValue()) + x + k);
        a.setValue(function.Ripemd_RotateLeft(a.getValue(), s) + e.getValue());
        c.setValue(function.Ripemd_RotateLeft(c.getValue(), 10));
    }


  /**
   * First transform set
   * 
   * @param   a1           int parameter by reference to be operated upon
   * @param   b1           int parameter by reference to be operated upon
   * @param   c1           int parameter by reference to be operated upon
   * @param   d1           int parameter by reference to be operated upon
   * @param   e1           int parameter by reference to be operated upon
   * @param   X            stream being hashed
   */
    protected void Transform_F0(BaseHash_Int a1, BaseHash_Int b1, BaseHash_Int c1, BaseHash_Int d1, BaseHash_Int e1, int[] X) {
      
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, a1, b1, c1, d1, e1, X[ 0], BaseRipemd.RL_0_15[ 0], BaseRipemd.CONSTANT0);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, e1, a1, b1, c1, d1, X[ 1], BaseRipemd.RL_0_15[ 1], BaseRipemd.CONSTANT0);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, d1, e1, a1, b1, c1, X[ 2], BaseRipemd.RL_0_15[ 2], BaseRipemd.CONSTANT0);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, c1, d1, e1, a1, b1, X[ 3], BaseRipemd.RL_0_15[ 3], BaseRipemd.CONSTANT0);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, b1, c1, d1, e1, a1, X[ 4], BaseRipemd.RL_0_15[ 4], BaseRipemd.CONSTANT0);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, a1, b1, c1, d1, e1, X[ 5], BaseRipemd.RL_0_15[ 5], BaseRipemd.CONSTANT0);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, e1, a1, b1, c1, d1, X[ 6], BaseRipemd.RL_0_15[ 6], BaseRipemd.CONSTANT0);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, d1, e1, a1, b1, c1, X[ 7], BaseRipemd.RL_0_15[ 7], BaseRipemd.CONSTANT0);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, c1, d1, e1, a1, b1, X[ 8], BaseRipemd.RL_0_15[ 8], BaseRipemd.CONSTANT0);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, b1, c1, d1, e1, a1, X[ 9], BaseRipemd.RL_0_15[ 9], BaseRipemd.CONSTANT0);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, a1, b1, c1, d1, e1, X[10], BaseRipemd.RL_0_15[10], BaseRipemd.CONSTANT0);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, e1, a1, b1, c1, d1, X[11], BaseRipemd.RL_0_15[11], BaseRipemd.CONSTANT0);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, d1, e1, a1, b1, c1, X[12], BaseRipemd.RL_0_15[12], BaseRipemd.CONSTANT0);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, c1, d1, e1, a1, b1, X[13], BaseRipemd.RL_0_15[13], BaseRipemd.CONSTANT0);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, b1, c1, d1, e1, a1, X[14], BaseRipemd.RL_0_15[14], BaseRipemd.CONSTANT0);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, a1, b1, c1, d1, e1, X[15], BaseRipemd.RL_0_15[15], BaseRipemd.CONSTANT0);
    }

  /**
   * Second transform set
   * 
   * @param   a1           int parameter by reference to be operated upon
   * @param   b1           int parameter by reference to be operated upon
   * @param   c1           int parameter by reference to be operated upon
   * @param   d1           int parameter by reference to be operated upon
   * @param   e1           int parameter by reference to be operated upon
   * @param   X            stream being hashed
   */
    protected void Transform_G1(BaseHash_Int a1, BaseHash_Int b1, BaseHash_Int c1, BaseHash_Int d1, BaseHash_Int e1, int[] X) {
      
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, e1, a1, b1, c1, d1, X[ 7], BaseRipemd.RL_16_31[ 0], BaseRipemd.CONSTANT1);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, d1, e1, a1, b1, c1, X[ 4], BaseRipemd.RL_16_31[ 1], BaseRipemd.CONSTANT1);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, c1, d1, e1, a1, b1, X[13], BaseRipemd.RL_16_31[ 2], BaseRipemd.CONSTANT1);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, b1, c1, d1, e1, a1, X[ 1], BaseRipemd.RL_16_31[ 3], BaseRipemd.CONSTANT1);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, a1, b1, c1, d1, e1, X[10], BaseRipemd.RL_16_31[ 4], BaseRipemd.CONSTANT1);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, e1, a1, b1, c1, d1, X[ 6], BaseRipemd.RL_16_31[ 5], BaseRipemd.CONSTANT1);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, d1, e1, a1, b1, c1, X[15], BaseRipemd.RL_16_31[ 6], BaseRipemd.CONSTANT1);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, c1, d1, e1, a1, b1, X[ 3], BaseRipemd.RL_16_31[ 7], BaseRipemd.CONSTANT1);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, b1, c1, d1, e1, a1, X[12], BaseRipemd.RL_16_31[ 8], BaseRipemd.CONSTANT1);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, a1, b1, c1, d1, e1, X[ 0], BaseRipemd.RL_16_31[ 9], BaseRipemd.CONSTANT1);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, e1, a1, b1, c1, d1, X[ 9], BaseRipemd.RL_16_31[10], BaseRipemd.CONSTANT1);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, d1, e1, a1, b1, c1, X[ 5], BaseRipemd.RL_16_31[11], BaseRipemd.CONSTANT1);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, c1, d1, e1, a1, b1, X[ 2], BaseRipemd.RL_16_31[12], BaseRipemd.CONSTANT1);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, b1, c1, d1, e1, a1, X[14], BaseRipemd.RL_16_31[13], BaseRipemd.CONSTANT1);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, a1, b1, c1, d1, e1, X[11], BaseRipemd.RL_16_31[14], BaseRipemd.CONSTANT1);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, e1, a1, b1, c1, d1, X[ 8], BaseRipemd.RL_16_31[15], BaseRipemd.CONSTANT1);
    }

  /**
   * Third transform set
   * 
   * @param   a1           int parameter by reference to be operated upon
   * @param   b1           int parameter by reference to be operated upon
   * @param   c1           int parameter by reference to be operated upon
   * @param   d1           int parameter by reference to be operated upon
   * @param   e1           int parameter by reference to be operated upon
   * @param   X            stream being hashed
   */
    protected void Transform_H2(BaseHash_Int a1, BaseHash_Int b1, BaseHash_Int c1, BaseHash_Int d1, BaseHash_Int e1, int[] X) {
      
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, d1, e1, a1, b1, c1, X[ 3], BaseRipemd.RL_32_47[ 0], BaseRipemd.CONSTANT2);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, c1, d1, e1, a1, b1, X[10], BaseRipemd.RL_32_47[ 1], BaseRipemd.CONSTANT2);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, b1, c1, d1, e1, a1, X[14], BaseRipemd.RL_32_47[ 2], BaseRipemd.CONSTANT2);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, a1, b1, c1, d1, e1, X[ 4], BaseRipemd.RL_32_47[ 3], BaseRipemd.CONSTANT2);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, e1, a1, b1, c1, d1, X[ 9], BaseRipemd.RL_32_47[ 4], BaseRipemd.CONSTANT2);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, d1, e1, a1, b1, c1, X[15], BaseRipemd.RL_32_47[ 5], BaseRipemd.CONSTANT2);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, c1, d1, e1, a1, b1, X[ 8], BaseRipemd.RL_32_47[ 6], BaseRipemd.CONSTANT2);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, b1, c1, d1, e1, a1, X[ 1], BaseRipemd.RL_32_47[ 7], BaseRipemd.CONSTANT2);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, a1, b1, c1, d1, e1, X[ 2], BaseRipemd.RL_32_47[ 8], BaseRipemd.CONSTANT2);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, e1, a1, b1, c1, d1, X[ 7], BaseRipemd.RL_32_47[ 9], BaseRipemd.CONSTANT2);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, d1, e1, a1, b1, c1, X[ 0], BaseRipemd.RL_32_47[10], BaseRipemd.CONSTANT2);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, c1, d1, e1, a1, b1, X[ 6], BaseRipemd.RL_32_47[11], BaseRipemd.CONSTANT2);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, b1, c1, d1, e1, a1, X[13], BaseRipemd.RL_32_47[12], BaseRipemd.CONSTANT2);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, a1, b1, c1, d1, e1, X[11], BaseRipemd.RL_32_47[13], BaseRipemd.CONSTANT2);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, e1, a1, b1, c1, d1, X[ 5], BaseRipemd.RL_32_47[14], BaseRipemd.CONSTANT2);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, d1, e1, a1, b1, c1, X[12], BaseRipemd.RL_32_47[15], BaseRipemd.CONSTANT2);
    }

  /**
   * Fourth transform set
   * 
   * @param   a1           int parameter by reference to be operated upon
   * @param   b1           int parameter by reference to be operated upon
   * @param   c1           int parameter by reference to be operated upon
   * @param   d1           int parameter by reference to be operated upon
   * @param   e1           int parameter by reference to be operated upon
   * @param   X            stream being hashed
   */
    protected void Transform_I3(BaseHash_Int a1, BaseHash_Int b1, BaseHash_Int c1, BaseHash_Int d1, BaseHash_Int e1, int[] X) {
      
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, c1, d1, e1, a1, b1, X[ 1], BaseRipemd.RL_48_63[ 0], BaseRipemd.CONSTANT3);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, b1, c1, d1, e1, a1, X[ 9], BaseRipemd.RL_48_63[ 1], BaseRipemd.CONSTANT3);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, a1, b1, c1, d1, e1, X[11], BaseRipemd.RL_48_63[ 2], BaseRipemd.CONSTANT3);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, e1, a1, b1, c1, d1, X[10], BaseRipemd.RL_48_63[ 3], BaseRipemd.CONSTANT3);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, d1, e1, a1, b1, c1, X[ 0], BaseRipemd.RL_48_63[ 4], BaseRipemd.CONSTANT3);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, c1, d1, e1, a1, b1, X[ 8], BaseRipemd.RL_48_63[ 5], BaseRipemd.CONSTANT3);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, b1, c1, d1, e1, a1, X[12], BaseRipemd.RL_48_63[ 6], BaseRipemd.CONSTANT3);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, a1, b1, c1, d1, e1, X[ 4], BaseRipemd.RL_48_63[ 7], BaseRipemd.CONSTANT3);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, e1, a1, b1, c1, d1, X[13], BaseRipemd.RL_48_63[ 8], BaseRipemd.CONSTANT3);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, d1, e1, a1, b1, c1, X[ 3], BaseRipemd.RL_48_63[ 9], BaseRipemd.CONSTANT3);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, c1, d1, e1, a1, b1, X[ 7], BaseRipemd.RL_48_63[10], BaseRipemd.CONSTANT3);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, b1, c1, d1, e1, a1, X[15], BaseRipemd.RL_48_63[11], BaseRipemd.CONSTANT3);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, a1, b1, c1, d1, e1, X[14], BaseRipemd.RL_48_63[12], BaseRipemd.CONSTANT3);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, e1, a1, b1, c1, d1, X[ 5], BaseRipemd.RL_48_63[13], BaseRipemd.CONSTANT3);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, d1, e1, a1, b1, c1, X[ 6], BaseRipemd.RL_48_63[14], BaseRipemd.CONSTANT3);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, c1, d1, e1, a1, b1, X[ 2], BaseRipemd.RL_48_63[15], BaseRipemd.CONSTANT3);
    }

  /**
   * Fifth transform set
   * 
   * @param   a1           int parameter by reference to be operated upon
   * @param   b1           int parameter by reference to be operated upon
   * @param   c1           int parameter by reference to be operated upon
   * @param   d1           int parameter by reference to be operated upon
   * @param   e1           int parameter by reference to be operated upon
   * @param   X            stream being hashed
   */
    protected void Transform_J4(BaseHash_Int a1, BaseHash_Int b1, BaseHash_Int c1, BaseHash_Int d1, BaseHash_Int e1, int[] X) {
      
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, b1, c1, d1, e1, a1, X[ 4], BaseRipemd160X.RL_64_79[ 0], BaseRipemd160X.CONSTANT4);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, a1, b1, c1, d1, e1, X[ 0], BaseRipemd160X.RL_64_79[ 1], BaseRipemd160X.CONSTANT4);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, e1, a1, b1, c1, d1, X[ 5], BaseRipemd160X.RL_64_79[ 2], BaseRipemd160X.CONSTANT4);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, d1, e1, a1, b1, c1, X[ 9], BaseRipemd160X.RL_64_79[ 3], BaseRipemd160X.CONSTANT4);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, c1, d1, e1, a1, b1, X[ 7], BaseRipemd160X.RL_64_79[ 4], BaseRipemd160X.CONSTANT4);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, b1, c1, d1, e1, a1, X[12], BaseRipemd160X.RL_64_79[ 5], BaseRipemd160X.CONSTANT4);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, a1, b1, c1, d1, e1, X[ 2], BaseRipemd160X.RL_64_79[ 6], BaseRipemd160X.CONSTANT4);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, e1, a1, b1, c1, d1, X[10], BaseRipemd160X.RL_64_79[ 7], BaseRipemd160X.CONSTANT4);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, d1, e1, a1, b1, c1, X[14], BaseRipemd160X.RL_64_79[ 8], BaseRipemd160X.CONSTANT4);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, c1, d1, e1, a1, b1, X[ 1], BaseRipemd160X.RL_64_79[ 9], BaseRipemd160X.CONSTANT4);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, b1, c1, d1, e1, a1, X[ 3], BaseRipemd160X.RL_64_79[10], BaseRipemd160X.CONSTANT4);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, a1, b1, c1, d1, e1, X[ 8], BaseRipemd160X.RL_64_79[11], BaseRipemd160X.CONSTANT4);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, e1, a1, b1, c1, d1, X[11], BaseRipemd160X.RL_64_79[12], BaseRipemd160X.CONSTANT4);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, d1, e1, a1, b1, c1, X[ 6], BaseRipemd160X.RL_64_79[13], BaseRipemd160X.CONSTANT4);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, c1, d1, e1, a1, b1, X[15], BaseRipemd160X.RL_64_79[14], BaseRipemd160X.CONSTANT4);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, b1, c1, d1, e1, a1, X[13], BaseRipemd160X.RL_64_79[15], BaseRipemd160X.CONSTANT4);
    }

  /**
   * Sixth transform set
   * 
   * @param   a2           int parameter by reference to be operated upon
   * @param   b2           int parameter by reference to be operated upon
   * @param   c2           int parameter by reference to be operated upon
   * @param   d2           int parameter by reference to be operated upon
   * @param   e2           int parameter by reference to be operated upon
   * @param   X            stream being hashed
   */
    protected void Transform_J5(BaseHash_Int a2, BaseHash_Int b2, BaseHash_Int c2, BaseHash_Int d2, BaseHash_Int e2, int[] X) {
      
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, a2, b2, c2, d2, e2, X[ 5], BaseRipemd.PRIME_RL_0_15[ 0], BaseRipemd.CONSTANT5);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, e2, a2, b2, c2, d2, X[14], BaseRipemd.PRIME_RL_0_15[ 1], BaseRipemd.CONSTANT5);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, d2, e2, a2, b2, c2, X[ 7], BaseRipemd.PRIME_RL_0_15[ 2], BaseRipemd.CONSTANT5);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, c2, d2, e2, a2, b2, X[ 0], BaseRipemd.PRIME_RL_0_15[ 3], BaseRipemd.CONSTANT5);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, b2, c2, d2, e2, a2, X[ 9], BaseRipemd.PRIME_RL_0_15[ 4], BaseRipemd.CONSTANT5);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, a2, b2, c2, d2, e2, X[ 2], BaseRipemd.PRIME_RL_0_15[ 5], BaseRipemd.CONSTANT5);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, e2, a2, b2, c2, d2, X[11], BaseRipemd.PRIME_RL_0_15[ 6], BaseRipemd.CONSTANT5);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, d2, e2, a2, b2, c2, X[ 4], BaseRipemd.PRIME_RL_0_15[ 7], BaseRipemd.CONSTANT5);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, c2, d2, e2, a2, b2, X[13], BaseRipemd.PRIME_RL_0_15[ 8], BaseRipemd.CONSTANT5);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, b2, c2, d2, e2, a2, X[ 6], BaseRipemd.PRIME_RL_0_15[ 9], BaseRipemd.CONSTANT5);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, a2, b2, c2, d2, e2, X[15], BaseRipemd.PRIME_RL_0_15[10], BaseRipemd.CONSTANT5);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, e2, a2, b2, c2, d2, X[ 8], BaseRipemd.PRIME_RL_0_15[11], BaseRipemd.CONSTANT5);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, d2, e2, a2, b2, c2, X[ 1], BaseRipemd.PRIME_RL_0_15[12], BaseRipemd.CONSTANT5);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, c2, d2, e2, a2, b2, X[10], BaseRipemd.PRIME_RL_0_15[13], BaseRipemd.CONSTANT5);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, b2, c2, d2, e2, a2, X[ 3], BaseRipemd.PRIME_RL_0_15[14], BaseRipemd.CONSTANT5);
        this.Ripemd_Transform160X(BaseRipemd160X.functionJ, a2, b2, c2, d2, e2, X[12], BaseRipemd.PRIME_RL_0_15[15], BaseRipemd.CONSTANT5);
    }

  /**
   * Seventh transform set
   * 
   * @param   a2           int parameter by reference to be operated upon
   * @param   b2           int parameter by reference to be operated upon
   * @param   c2           int parameter by reference to be operated upon
   * @param   d2           int parameter by reference to be operated upon
   * @param   e2           int parameter by reference to be operated upon
   * @param   X            stream being hashed
   */
    protected void Transform_I6(BaseHash_Int a2, BaseHash_Int b2, BaseHash_Int c2, BaseHash_Int d2, BaseHash_Int e2, int[] X) {
      
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, e2, a2, b2, c2, d2, X[ 6], BaseRipemd.PRIME_RL_16_31[ 0], BaseRipemd.CONSTANT6);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, d2, e2, a2, b2, c2, X[11], BaseRipemd.PRIME_RL_16_31[ 1], BaseRipemd.CONSTANT6);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, c2, d2, e2, a2, b2, X[ 3], BaseRipemd.PRIME_RL_16_31[ 2], BaseRipemd.CONSTANT6);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, b2, c2, d2, e2, a2, X[ 7], BaseRipemd.PRIME_RL_16_31[ 3], BaseRipemd.CONSTANT6);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, a2, b2, c2, d2, e2, X[ 0], BaseRipemd.PRIME_RL_16_31[ 4], BaseRipemd.CONSTANT6);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, e2, a2, b2, c2, d2, X[13], BaseRipemd.PRIME_RL_16_31[ 5], BaseRipemd.CONSTANT6);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, d2, e2, a2, b2, c2, X[ 5], BaseRipemd.PRIME_RL_16_31[ 6], BaseRipemd.CONSTANT6);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, c2, d2, e2, a2, b2, X[10], BaseRipemd.PRIME_RL_16_31[ 7], BaseRipemd.CONSTANT6);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, b2, c2, d2, e2, a2, X[14], BaseRipemd.PRIME_RL_16_31[ 8], BaseRipemd.CONSTANT6);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, a2, b2, c2, d2, e2, X[15], BaseRipemd.PRIME_RL_16_31[ 9], BaseRipemd.CONSTANT6);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, e2, a2, b2, c2, d2, X[ 8], BaseRipemd.PRIME_RL_16_31[10], BaseRipemd.CONSTANT6);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, d2, e2, a2, b2, c2, X[12], BaseRipemd.PRIME_RL_16_31[11], BaseRipemd.CONSTANT6);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, c2, d2, e2, a2, b2, X[ 4], BaseRipemd.PRIME_RL_16_31[12], BaseRipemd.CONSTANT6);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, b2, c2, d2, e2, a2, X[ 9], BaseRipemd.PRIME_RL_16_31[13], BaseRipemd.CONSTANT6);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, a2, b2, c2, d2, e2, X[ 1], BaseRipemd.PRIME_RL_16_31[14], BaseRipemd.CONSTANT6);
        this.Ripemd_Transform160X(BaseRipemd160X.functionI, e2, a2, b2, c2, d2, X[ 2], BaseRipemd.PRIME_RL_16_31[15], BaseRipemd.CONSTANT6);
    }

  /**
   * Eighth transform set
   * 
   * @param   a2           int parameter by reference to be operated upon
   * @param   b2           int parameter by reference to be operated upon
   * @param   c2           int parameter by reference to be operated upon
   * @param   d2           int parameter by reference to be operated upon
   * @param   e2           int parameter by reference to be operated upon
   * @param   X            stream being hashed
   */
    protected void Transform_H7(BaseHash_Int a2, BaseHash_Int b2, BaseHash_Int c2, BaseHash_Int d2, BaseHash_Int e2, int[] X) {
      
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, d2, e2, a2, b2, c2, X[15], BaseRipemd.PRIME_RL_32_47[ 0], BaseRipemd.CONSTANT7);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, c2, d2, e2, a2, b2, X[ 5], BaseRipemd.PRIME_RL_32_47[ 1], BaseRipemd.CONSTANT7);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, b2, c2, d2, e2, a2, X[ 1], BaseRipemd.PRIME_RL_32_47[ 2], BaseRipemd.CONSTANT7);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, a2, b2, c2, d2, e2, X[ 3], BaseRipemd.PRIME_RL_32_47[ 3], BaseRipemd.CONSTANT7);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, e2, a2, b2, c2, d2, X[ 7], BaseRipemd.PRIME_RL_32_47[ 4], BaseRipemd.CONSTANT7);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, d2, e2, a2, b2, c2, X[14], BaseRipemd.PRIME_RL_32_47[ 5], BaseRipemd.CONSTANT7);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, c2, d2, e2, a2, b2, X[ 6], BaseRipemd.PRIME_RL_32_47[ 6], BaseRipemd.CONSTANT7);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, b2, c2, d2, e2, a2, X[ 9], BaseRipemd.PRIME_RL_32_47[ 7], BaseRipemd.CONSTANT7);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, a2, b2, c2, d2, e2, X[11], BaseRipemd.PRIME_RL_32_47[ 8], BaseRipemd.CONSTANT7);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, e2, a2, b2, c2, d2, X[ 8], BaseRipemd.PRIME_RL_32_47[ 9], BaseRipemd.CONSTANT7);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, d2, e2, a2, b2, c2, X[12], BaseRipemd.PRIME_RL_32_47[10], BaseRipemd.CONSTANT7);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, c2, d2, e2, a2, b2, X[ 2], BaseRipemd.PRIME_RL_32_47[11], BaseRipemd.CONSTANT7);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, b2, c2, d2, e2, a2, X[10], BaseRipemd.PRIME_RL_32_47[12], BaseRipemd.CONSTANT7);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, a2, b2, c2, d2, e2, X[ 0], BaseRipemd.PRIME_RL_32_47[13], BaseRipemd.CONSTANT7);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, e2, a2, b2, c2, d2, X[ 4], BaseRipemd.PRIME_RL_32_47[14], BaseRipemd.CONSTANT7);
        this.Ripemd_Transform160X(BaseRipemd160X.functionH, d2, e2, a2, b2, c2, X[13], BaseRipemd.PRIME_RL_32_47[15], BaseRipemd.CONSTANT7);
    }

  /**
   * Ninth transform set
   * 
   * @param   a2           int parameter by reference to be operated upon
   * @param   b2           int parameter by reference to be operated upon
   * @param   c2           int parameter by reference to be operated upon
   * @param   d2           int parameter by reference to be operated upon
   * @param   e2           int parameter by reference to be operated upon
   * @param   X            stream being hashed
   */
    protected void Transform_G8(BaseHash_Int a2, BaseHash_Int b2, BaseHash_Int c2, BaseHash_Int d2, BaseHash_Int e2, int[] X) {
      
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, c2, d2, e2, a2, b2, X[ 8], BaseRipemd.PRIME_RL_48_63[ 0], BaseRipemd160X.CONSTANT8);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, b2, c2, d2, e2, a2, X[ 6], BaseRipemd.PRIME_RL_48_63[ 1], BaseRipemd160X.CONSTANT8);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, a2, b2, c2, d2, e2, X[ 4], BaseRipemd.PRIME_RL_48_63[ 2], BaseRipemd160X.CONSTANT8);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, e2, a2, b2, c2, d2, X[ 1], BaseRipemd.PRIME_RL_48_63[ 3], BaseRipemd160X.CONSTANT8);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, d2, e2, a2, b2, c2, X[ 3], BaseRipemd.PRIME_RL_48_63[ 4], BaseRipemd160X.CONSTANT8);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, c2, d2, e2, a2, b2, X[11], BaseRipemd.PRIME_RL_48_63[ 5], BaseRipemd160X.CONSTANT8);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, b2, c2, d2, e2, a2, X[15], BaseRipemd.PRIME_RL_48_63[ 6], BaseRipemd160X.CONSTANT8);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, a2, b2, c2, d2, e2, X[ 0], BaseRipemd.PRIME_RL_48_63[ 7], BaseRipemd160X.CONSTANT8);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, e2, a2, b2, c2, d2, X[ 5], BaseRipemd.PRIME_RL_48_63[ 8], BaseRipemd160X.CONSTANT8);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, d2, e2, a2, b2, c2, X[12], BaseRipemd.PRIME_RL_48_63[ 9], BaseRipemd160X.CONSTANT8);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, c2, d2, e2, a2, b2, X[ 2], BaseRipemd.PRIME_RL_48_63[10], BaseRipemd160X.CONSTANT8);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, b2, c2, d2, e2, a2, X[13], BaseRipemd.PRIME_RL_48_63[11], BaseRipemd160X.CONSTANT8);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, a2, b2, c2, d2, e2, X[ 9], BaseRipemd.PRIME_RL_48_63[12], BaseRipemd160X.CONSTANT8);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, e2, a2, b2, c2, d2, X[ 7], BaseRipemd.PRIME_RL_48_63[13], BaseRipemd160X.CONSTANT8);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, d2, e2, a2, b2, c2, X[10], BaseRipemd.PRIME_RL_48_63[14], BaseRipemd160X.CONSTANT8);
        this.Ripemd_Transform160X(BaseRipemd160X.functionG, c2, d2, e2, a2, b2, X[14], BaseRipemd.PRIME_RL_48_63[15], BaseRipemd160X.CONSTANT8);
    }

  /**
   * Tenth transform set
   * 
   * @param   a2           int parameter by reference to be operated upon
   * @param   b2           int parameter by reference to be operated upon
   * @param   c2           int parameter by reference to be operated upon
   * @param   d2           int parameter by reference to be operated upon
   * @param   e2           int parameter by reference to be operated upon
   * @param   X            stream being hashed
   */
    protected void Transform_F9(BaseHash_Int a2, BaseHash_Int b2, BaseHash_Int c2, BaseHash_Int d2, BaseHash_Int e2, int[] X) {
      
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, b2, c2, d2, e2, a2, X[12], BaseRipemd160X.PRIME_RL_64_79[ 0], BaseRipemd.CONSTANT9);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, a2, b2, c2, d2, e2, X[15], BaseRipemd160X.PRIME_RL_64_79[ 1], BaseRipemd.CONSTANT9);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, e2, a2, b2, c2, d2, X[10], BaseRipemd160X.PRIME_RL_64_79[ 2], BaseRipemd.CONSTANT9);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, d2, e2, a2, b2, c2, X[ 4], BaseRipemd160X.PRIME_RL_64_79[ 3], BaseRipemd.CONSTANT9);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, c2, d2, e2, a2, b2, X[ 1], BaseRipemd160X.PRIME_RL_64_79[ 4], BaseRipemd.CONSTANT9);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, b2, c2, d2, e2, a2, X[ 5], BaseRipemd160X.PRIME_RL_64_79[ 5], BaseRipemd.CONSTANT9);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, a2, b2, c2, d2, e2, X[ 8], BaseRipemd160X.PRIME_RL_64_79[ 6], BaseRipemd.CONSTANT9);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, e2, a2, b2, c2, d2, X[ 7], BaseRipemd160X.PRIME_RL_64_79[ 7], BaseRipemd.CONSTANT9);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, d2, e2, a2, b2, c2, X[ 6], BaseRipemd160X.PRIME_RL_64_79[ 8], BaseRipemd.CONSTANT9);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, c2, d2, e2, a2, b2, X[ 2], BaseRipemd160X.PRIME_RL_64_79[ 9], BaseRipemd.CONSTANT9);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, b2, c2, d2, e2, a2, X[13], BaseRipemd160X.PRIME_RL_64_79[10], BaseRipemd.CONSTANT9);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, a2, b2, c2, d2, e2, X[14], BaseRipemd160X.PRIME_RL_64_79[11], BaseRipemd.CONSTANT9);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, e2, a2, b2, c2, d2, X[ 0], BaseRipemd160X.PRIME_RL_64_79[12], BaseRipemd.CONSTANT9);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, d2, e2, a2, b2, c2, X[ 3], BaseRipemd160X.PRIME_RL_64_79[13], BaseRipemd.CONSTANT9);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, c2, d2, e2, a2, b2, X[ 9], BaseRipemd160X.PRIME_RL_64_79[14], BaseRipemd.CONSTANT9);
        this.Ripemd_Transform160X(BaseRipemd160X.functionF, b2, c2, d2, e2, a2, X[11], BaseRipemd160X.PRIME_RL_64_79[15], BaseRipemd.CONSTANT9);
    }

  /**
   * Constructor, default 
   */
    public BaseRipemd160X() {
        super();
    }

  /**
   * Destructor 
   */
    public void finalize() {
      
    }

  /**
   * Initializes state of Ripmed 160 and 320 algorithms 
   */
    public void Initialize() {
      
        super.Initialize();
        this.messageDigest.SetULPosition(4, BaseRipemd160X.INISTATE4);
    }

}
