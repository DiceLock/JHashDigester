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
  * Base long class for some hash functions that allows to pass long type parameter to methods by reference
  * 
  * @author      Angel Ferré @ DiceLock Security
  * @version     5.0.0.1
  * @since       2011-10-03
  */
public class BaseHash_Long {
  
  /**
   * Long value, stored one element array 
   */
    protected long[] value = new long[1];
  
  /**
   * Constructor, default
   */
    public BaseHash_Long() {
        super();
    }

  /**
   * Destructor, zeroes all data
   * 
   */
    public void finalize() {
    
        value[0] = 0;
    }
    
  /**
   * Set the long as BaseHash_Long long value
   * 
   * @param   x     long value to be stored in BaseHash_Long
   */
    public void setValue(long x) {
        
        value[0] = x;
    }
  
  /**
   * Get the long value stored in BaseHash_Long
   * 
   * @return   long:     long value strored in BaseHash_Long
   */
    public long getValue() {
      
        return value[0];
    }
}