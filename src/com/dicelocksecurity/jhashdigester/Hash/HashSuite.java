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

import com.dicelocksecurity.jhashdigester.CryptoRandomStream.*;

/**
 * Suite class to perform any selected hash algorithm on stream bits 
 * 
 * @author      Angel Ferré @ DiceLock Security
 * @version     5.0.0.1
 * @since       2011-11-03
 */
public class HashSuite {

  /**
   * Points the first hash algorithm in the suite
   */
	protected static final	Hashes firstHash = Hashes.SHA_1;

  /**
   * Array holding instantiated hash algorithm objects 
   */
	protected BaseHash[]	suite = new BaseHash[Hashes.NumberOfHashes.ordinal()];
  /**
   * Array holding booleans pointing out if instantiated hash algorithm objects has been internally created 
   */
	protected boolean[]	selfCreatedHash = new boolean[Hashes.NumberOfHashes.ordinal()];
  /**
   * Number of instantiated hash algorithm objects in the suite 
   */
	protected short		instantiatedHashes;

  /**
   * Constructor, default, initializes suite 
   */
	public HashSuite() {
		int i;

		for (i = this.GetFirstHash().ordinal(); i < this.GetMaximumNumberOfHashes().ordinal(); i++) {
			this.suite[i] = null;
			this.selfCreatedHash[i] = false;
		}
		this.instantiatedHashes = 0;
	}

  /**
   * Destructor
   */
	public void finalize() {
		int i;

		for (i = this.GetFirstHash().ordinal(); i < this.GetMaximumNumberOfHashes().ordinal(); i++) {
			if (this.suite[i] != null) {
				this.suite[i] = null;
			    this.selfCreatedHash[i] = false;
			}
		}
		this.instantiatedHashes = 0;
	}

		// ADDING HASHES
		
  /**
   * Adds a hash to the suite
   * 
   * @param		hash	hash algorithm object added to the suite
   */
	public void Add(BaseHash hash) {
		
		if (hash != null) {
			this.suite[hash.GetType().ordinal()] = hash;
			this.selfCreatedHash[hash.GetType().ordinal()] = false;
			this.instantiatedHashes++;
		}
	}

  /**
   * Creates and adds a hash to the suite based in the enumerated hash list
   * 
   * @param		hash	hash algorithm as enumerated parameter to be added to the suite
   */
	public void Add(Hashes hash) {
		
		switch (hash) {
			case SHA_1: 
				if (this.suite[Hashes.SHA_1.ordinal()] == null) {
					this.suite[Hashes.SHA_1.ordinal()] = new Sha1();
					this.instantiatedHashes++;
				}
				break;
			case SHA_224: 
				if (this.suite[Hashes.SHA_224.ordinal()] == null) {
					this.suite[Hashes.SHA_224.ordinal()] = new Sha224();
					this.instantiatedHashes++;
				}
				break;
			case SHA_256: 
				if (this.suite[Hashes.SHA_256.ordinal()] == null) {
					this.suite[Hashes.SHA_256.ordinal()] = new Sha256();
					this.instantiatedHashes++;
				}
				break;
			case SHA_384: 
				if (this.suite[Hashes.SHA_384.ordinal()] == null) {
					this.suite[Hashes.SHA_384.ordinal()] = new Sha384();
					this.instantiatedHashes++;
				}
				break;
			case SHA_512: 
				if (this.suite[Hashes.SHA_512.ordinal()] == null) {
					this.suite[Hashes.SHA_512.ordinal()] = new Sha512();
					this.instantiatedHashes++;
				}
				break;
			case RIPEMD_128: 
				if (this.suite[Hashes.RIPEMD_128.ordinal()] == null) {
					this.suite[Hashes.RIPEMD_128.ordinal()] = new Ripemd128();
					this.instantiatedHashes++;
				}
				break;
			case RIPEMD_160: 
				if (this.suite[Hashes.RIPEMD_160.ordinal()] == null) {
					this.suite[Hashes.RIPEMD_160.ordinal()] = new Ripemd160();
					this.instantiatedHashes++;
				}
				break;
			case RIPEMD_256: 
				if (this.suite[Hashes.RIPEMD_256.ordinal()] == null) {
					this.suite[Hashes.RIPEMD_256.ordinal()] = new Ripemd256();
					this.instantiatedHashes++;
				}
				break;
			case RIPEMD_320: 
				if (this.suite[Hashes.RIPEMD_320.ordinal()] == null) {
					this.suite[Hashes.RIPEMD_320.ordinal()] = new Ripemd320();
					this.instantiatedHashes++;
				}
				break;
			default:
				break;
		}
		this.selfCreatedHash[hash.ordinal()] = true;
	}

  /**
   * Creates and adds all hash algorithms to the suite
   */
	public void AddAll() {
		int i;

		this.suite[Hashes.SHA_1.ordinal()] = new Sha1();
		this.suite[Hashes.SHA_224.ordinal()] = new Sha224();
		this.suite[Hashes.SHA_256.ordinal()] = new Sha256();
		this.suite[Hashes.SHA_384.ordinal()] = new Sha384();
		this.suite[Hashes.SHA_512.ordinal()] = new Sha512();
		this.suite[Hashes.RIPEMD_128.ordinal()] = new Ripemd128();
		this.suite[Hashes.RIPEMD_160.ordinal()] = new Ripemd160();
		this.suite[Hashes.RIPEMD_256.ordinal()] = new Ripemd256();
		this.suite[Hashes.RIPEMD_320.ordinal()] = new Ripemd320();
		for (i = this.GetFirstHash().ordinal(); i < this.GetMaximumNumberOfHashes().ordinal(); i++) {
			this.selfCreatedHash[i] = true;
		}
		this.instantiatedHashes = (short)Hashes.NumberOfHashes.ordinal();
	}

  /**
   * Creates and adds defined hash to the suite
   */
	public void AddSha1() {
		
		this.suite[Hashes.SHA_1.ordinal()] = new Sha1();
		this.selfCreatedHash[Hashes.SHA_1.ordinal()] = true;
		this.instantiatedHashes++;
	}

  /**
   * Creates and adds defined hash to the suite
   */
	public void AddSha224() {
		
		this.suite[Hashes.SHA_224.ordinal()] = new Sha224();
		this.selfCreatedHash[Hashes.SHA_224.ordinal()] = true;
		this.instantiatedHashes++;
	}

  /**
   * Creates and adds defined hash to the suite
   */
	public void AddSha256() {
		
		this.suite[Hashes.SHA_256.ordinal()] = new Sha256();
		this.selfCreatedHash[Hashes.SHA_256.ordinal()] = true;
		this.instantiatedHashes++;
	}

  /**
   * Creates and adds defined hash to the suite
   */
	public void AddSha384() {
		
		this.suite[Hashes.SHA_384.ordinal()] = new Sha384();
		this.selfCreatedHash[Hashes.SHA_384.ordinal()] = true;
		this.instantiatedHashes++;
	}

  /**
   * Creates and adds defined hash to the suite
   */
	public void AddSha512() {
		
		this.suite[Hashes.SHA_512.ordinal()] = new Sha512();
		this.selfCreatedHash[Hashes.SHA_512.ordinal()] = true;
		this.instantiatedHashes++;
	}

  /**
   * Creates and adds defined hash to the suite
   */
	public void AddRipemd128() {
		
		this.suite[Hashes.RIPEMD_128.ordinal()] = new Ripemd128();
		this.selfCreatedHash[Hashes.RIPEMD_128.ordinal()] = true;
		this.instantiatedHashes++;
	}

  /**
   * Creates and adds defined hash to the suite
   */
	public void AddRipemd160() {
		
		this.suite[Hashes.RIPEMD_160.ordinal()] = new Ripemd160();
		this.selfCreatedHash[Hashes.RIPEMD_160.ordinal()] = true;
		this.instantiatedHashes++;
	}

  /**
   * Creates and adds defined hash to the suite
   */
	public void AddRipemd256() {
		
		this.suite[Hashes.RIPEMD_256.ordinal()] = new Ripemd256();
		this.selfCreatedHash[Hashes.RIPEMD_256.ordinal()] = true;
		this.instantiatedHashes++;
	}

  /**
   * Creates and adds defined hash to the suite
   */
	public void AddRipemd320() {
		
		this.suite[Hashes.RIPEMD_320.ordinal()] = new Ripemd320();
		this.selfCreatedHash[Hashes.RIPEMD_320.ordinal()] = true;
		this.instantiatedHashes++;
	}

		// GETTING HASH OBJECT
		
  /**
   * Gets a hash algorithm from the suite based in the enumerated hash
   * 
   * @param		hash	hash algorithm as enumerated parameter to be selected
   */
	public BaseHash GetMessageDigest(Hashes hash) {
		
		return this.suite[hash.ordinal()];
	}

  /**
   * Gets defined hash from the suite
   */
	public Sha1 GetSha1() {
		
		return (Sha1)this.suite[Hashes.SHA_1.ordinal()];
	}

  /**
   * Gets defined hash from the suite
   */
	public Sha224 GetSha224() {
		
		return (Sha224)this.suite[Hashes.SHA_224.ordinal()];
	}

  /**
   * Gets defined hash from the suite
   */
	public Sha256 GetSha256() {
		
		return (Sha256)this.suite[Hashes.SHA_256.ordinal()];
	}

  /**
   * Gets defined hash from the suite
   */
	public Sha384 GetSha384() {
		
		return (Sha384)this.suite[Hashes.SHA_384.ordinal()];
	}

  /**
   * Gets defined hash from the suite
   */
	public Sha512 GetSha512() {
		
		return (Sha512)this.suite[Hashes.SHA_512.ordinal()];
	}

  /**
   * Gets defined hash from the suite
   */
	public Ripemd128 GetRipemd128() {
		
		return (Ripemd128)this.suite[Hashes.RIPEMD_128.ordinal()];
	}

  /**
   * Gets defined hash from the suite
   */
	public Ripemd160 GetRipemd160() {
		
		return (Ripemd160)this.suite[Hashes.RIPEMD_160.ordinal()];
	}

  /**
   * Gets defined hash from the suite
   */
	public Ripemd256 GetRipemd256() {
		
		return (Ripemd256)this.suite[Hashes.RIPEMD_256.ordinal()];
	}

  /**
   * Gets defined hash from the suite
   */
	public Ripemd320 GetRipemd320() {
		
		return (Ripemd320)this.suite[Hashes.RIPEMD_320.ordinal()];
	}

		// REMOVING HASH ALGORITHMS

  /**
   * Removes the pointed hash from the suite
   * 
   * @param		hashObject		hash object to be removed from the suite
   */
	public void Remove(BaseHash hashObject) {
		Hashes hash;

		hash = hashObject.GetType();
		if ((this.suite[hash.ordinal()] != null) && (this.suite[hash.ordinal()] == hashObject)) {
			if (this.selfCreatedHash[hash.ordinal()]) {
				this.suite[hash.ordinal()] = null;
			}
			this.suite[hash.ordinal()] = null;
			this.selfCreatedHash[hash.ordinal()] = false;
			this.instantiatedHashes--;
		}
	}

  /**
   * Removes a hash from the suite based in the enumerated hash algorithms
   * 
   * @param		hash		hash algorithm as enumerated parameter to be removed from the suite
   */
	public void Remove(Hashes hash) {
		
		if (this.suite[hash.ordinal()] != null) {
			if (this.selfCreatedHash[hash.ordinal()]) {
				this.suite[hash.ordinal()] = null;
			}
			this.suite[hash.ordinal()] = null;
			this.selfCreatedHash[hash.ordinal()] = false;
			this.instantiatedHashes--;
		}
	}

  /**
   * Removes all hash algorithms from the suite
   */
	public void RemoveAll() {
		int i;

		for (i = this.GetFirstHash().ordinal(); i < this.GetMaximumNumberOfHashes().ordinal(); i++) {
			if (this.suite[i] != null) {
				if (this.selfCreatedHash[i]) {
					this.suite[i] = null;
				}
				this.suite[i] = null;
			    this.selfCreatedHash[i] = false;
			}
		}
		this.instantiatedHashes = 0;
	}

  /**
   * Removes defined hash from the suite
   */
	public void RemoveSha1() {
		
		if (this.suite[Hashes.SHA_1.ordinal()] != null) {
			this.suite[Hashes.SHA_1.ordinal()] = null;
		    this.selfCreatedHash[Hashes.SHA_1.ordinal()] = false;
			this.instantiatedHashes--;
		}
	}

  /**
   * Removes defined hash from the suite
   */
	public void RemoveSha224() {
		
		if (this.suite[Hashes.SHA_224.ordinal()] != null) {
			this.suite[Hashes.SHA_224.ordinal()] = null;
		    this.selfCreatedHash[Hashes.SHA_224.ordinal()] = false;
			this.instantiatedHashes--;
		}
	}

  /**
   * Removes defined hash from the suite
   */
	public void RemoveSha256() {
		
		if (this.suite[Hashes.SHA_256.ordinal()] != null) {
			this.suite[Hashes.SHA_256.ordinal()] = null;
		    this.selfCreatedHash[Hashes.SHA_256.ordinal()] = false;
			this.instantiatedHashes--;
		}
	}

  /**
   * Removes defined hash from the suite
   */
	public void RemoveSha384() {
		
		if (this.suite[Hashes.SHA_384.ordinal()] != null) {
			this.suite[Hashes.SHA_384.ordinal()] = null;
		    this.selfCreatedHash[Hashes.SHA_384.ordinal()] = false;
			this.instantiatedHashes--;
		}
	}

  /**
   * Removes defined hash from the suite
   */
	public void RemoveSha512() {
		
		if (this.suite[Hashes.SHA_512.ordinal()] != null) {
			this.suite[Hashes.SHA_512.ordinal()] = null;
		    this.selfCreatedHash[Hashes.SHA_512.ordinal()] = false;
			this.instantiatedHashes--;
		}
	}

  /**
   * Removes defined hash from the suite
   */
	public void RemoveRipemd128() {
		
		if (this.suite[Hashes.RIPEMD_128.ordinal()] != null) {
			this.suite[Hashes.RIPEMD_128.ordinal()] = null;
		    this.selfCreatedHash[Hashes.RIPEMD_128.ordinal()] = false;
			this.instantiatedHashes--;
		}
	}

  /**
   * Removes defined hash from the suite
   */
	public void RemoveRipemd160() {
		
		if (this.suite[Hashes.RIPEMD_160.ordinal()] != null) {
			this.suite[Hashes.RIPEMD_160.ordinal()] = null;
		    this.selfCreatedHash[Hashes.RIPEMD_160.ordinal()] = false;
			this.instantiatedHashes--;
		}
	}

  /**
   * Removes defined hash from the suite
   */
	public void RemoveRipemd256() {
		
		if (this.suite[Hashes.RIPEMD_256.ordinal()] != null) {
			this.suite[Hashes.RIPEMD_256.ordinal()] = null;
		    this.selfCreatedHash[Hashes.RIPEMD_256.ordinal()] = false;
			this.instantiatedHashes--;
		}
	}

  /**
   * Removes defined hash from the suite
   */
	public void RemoveRipemd320() {
		
		if (this.suite[Hashes.RIPEMD_320.ordinal()] != null) {
			this.suite[Hashes.RIPEMD_320.ordinal()] = null;
		    this.selfCreatedHash[Hashes.RIPEMD_320.ordinal()] = false;
			this.instantiatedHashes--;
		}
	}

		// PERFORMING HASH

  /**
   * Performs the hash algorithms of BaseCryptoRandomStream with all instantiated hash 
   */
	public void Hash(BaseCryptoRandomStream stream) {
		int i;
		
		this.Initialize();
		for (i = this.GetFirstHash().ordinal(); i < this.GetMaximumNumberOfHashes().ordinal(); i++) {
			if (this.suite[i] != null) {
				this.suite[i].Add(stream); 
				this.suite[i].Finalize(); 
			}
		}
	}

		// INITIALIZE SUITE
		
  /**
   * Initializes all hash algorithms in the suite
   */
	public void Initialize() {
		int i;
		
		for (i = this.GetFirstHash().ordinal(); i < this.GetMaximumNumberOfHashes().ordinal(); i++) {
			if (this.suite[i] != null) {
				this.suite[i].Initialize();
			}
		}
	}

		// ADDS STREAM TO THE SUITE
		
  /**
   * Adds BaseCryptoRandomStream stream to hash algorithms in the suite
   * 
   * @param		stream		bit stream to be added to hash
   */
	public void Add(BaseCryptoRandomStream stream) {
		int i;
		
		for (i = this.GetFirstHash().ordinal(); i < this.GetMaximumNumberOfHashes().ordinal(); i++) {
			if (this.suite[i] != null) {
				this.suite[i].Add(stream);
			}
		}
	}

		// FINALIZE THE SUITE
		
  /**
   * Finalize hash algorithms in the suite
   */
	public void Finalize() {
		int i;
		
		for (i = this.GetFirstHash().ordinal(); i < this.GetMaximumNumberOfHashes().ordinal(); i++) {
			if (this.suite[i] != null) {
				this.suite[i].Finalize();
			}
		}
	}

		// GETTING SUITE INFORMATION

  /**
   * Gets the number of hash algorithms that contains the suite
   * 
   * @return	short:		number of instantiated hash algorithm objects in the suite
   */
	public short GetInstantiatedHashes() {
		
		return this.instantiatedHashes;
	}

  /**
   * Indicates if a hash algorithm exists in the suite
   * 
   * @param		hash		hash algorithm as enumerated parameter to check if the corresponding hash object has been instantiated in the suite
   * @return	boolean		return "true" if corresponding hash algorithm object is instantiated in the suite, "false" otherwise	  
   */
	public 	boolean Exist(Hashes hash) {
		
		return (this.suite[hash.ordinal()] != null);
	}

  /**
   * Gets the first hash algorithm in the HashSuite
   * 
   * @return	Hashes		returns first instantiated hash algorithm object as enumerated type
   */
	public 	Hashes GetFirstHash() {
		
		return HashSuite.firstHash;
	}

  /**
   * Gets the number of hash algorithms that can be used in the HahsSuite
   * 
   * @return	Hashes		returns maximum number of hash algorithms allowed to be instantiated 
   */
	public Hashes GetMaximumNumberOfHashes() {
		
		return Hashes.NumberOfHashes;
	}

}
