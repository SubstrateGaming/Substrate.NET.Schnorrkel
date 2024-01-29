/*
 * Copyright (C) 2020 Usetech Professional
 * Copyright (C) 2021 BloGa Tech AG,
 * Copyright (C) 2024 SubstrateGaming
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using Substrate.NET.Schnorrkel.Exceptions;
using Substrate.NET.Schnorrkel.Keys;
using Substrate.NET.Schnorrkel.Merlin;
using Substrate.NET.Schnorrkel.Ristretto;
using Substrate.NET.Schnorrkel.Scalars;
using System;

namespace Substrate.NET.Schnorrkel
{
    /// <summary>
    /// A secret key for use with Ristretto Schnorr signatures.
    ///
    /// Internally, these consist of a scalar mod l along with a seed for
    /// nonce generation.  In this way, we ensure all scalar arithmatic
    /// works smoothly in operations like threshold or multi-signatures,
    /// or hierarchical deterministic key derivations.
    ///
    /// We keep our secret key serializaion "almost" compatable with EdDSA
    /// "expanded" secret key serializaion by multiplying the scalar by the
    /// cofactor 8, as integers, and dividing on deserializaion.
    /// We do not however attempt to keep the scalar's high bit set, especially
    /// not during hierarchical deterministic key derivations, so some Ed25519
    /// libraries might compute the public key incorrectly from our secret key.
    /// </summary>
    public struct SecretKey
    {
        /// Actual public key represented as a scalar.
        public Scalar key;

        /// Seed for deriving the nonces used in signing.
        ///
        /// We require this be random and secret or else key compromise attacks will ensue.
        /// Any modificaiton here may dirupt some non-public key derivation techniques.
        public byte[] nonce; //[u8; 32],

        /// <summary>
        /// Convert this `SecretKey` into an array of 64 bytes with.
        ///
        /// Returns an array of 64 bytes, with the first 32 bytes being
        /// the secret scalar represented cannonically, and the last
        /// 32 bytes being the seed for nonces.
        /// </summary>
        /// <returns></returns>
        public byte[] ToBytes()
        {
            var result = new byte[64];
            key.ScalarBytes.CopyTo(result, 0);
            nonce.CopyTo(result, 32);
            return result;
        }

        /// <summary>
        /// Derive the `PublicKey` corresponding to this `MiniSecretKey`.
        /// </summary>
        /// <returns></returns>
        public PublicKey ExpandToPublic()
        {
            var tbl = new RistrettoBasepointTable();
            var R = tbl.Mul(key).Compress();

            return new PublicKey(R.ToBytes());
        }

        /// <summary>
        /// Construct an `SecretKey` from a slice of bytes.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public static SecretKey FromBytes085(byte[] data)
        {
            if (data.Length != Consts.SIGNATURE_LENGTH)
                throw new SignatureException("SecretKey - SignatureError::BytesLengthError");

            return new SecretKey
            {
                key = new Scalar { ScalarBytes = data.AsMemory().Slice(0, 32).ToArray() },
                nonce = data.AsMemory().Slice(32, 32).ToArray()
            };
        }

        /// <summary>
        /// Construct an `SecretKey` from a slice of bytes, corresponding to an Ed25519 expanded secret key.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public static SecretKey FromBytes011(byte[] data)
        {
            if (data.Length != Consts.SIGNATURE_LENGTH)
                throw new ArgumentException("SecretKey - SignatureError::BytesLengthError");

            // TODO:  We should consider making sure the scalar is valid,
            // maybe by zering the high bit, orp referably by checking < l.
            // key[31] &= 0b0111_1111;
            // We devide by the cofactor to internally keep a clean
            // representation mod l.
            var dataSlice = data.AsMemory().Slice(0, 32).ToArray();
            Scalar.DivideScalarBytesByCofactor(ref dataSlice);//::divide_scalar_bytes_by_cofactor(&mut key);

            return new SecretKey
            {
                key = new Scalar { ScalarBytes = dataSlice },
                nonce = data.AsMemory().Slice(32, 32).ToArray()
            };
        }

        /// <summary>
        /// Convert this `SecretKey` into an array of 64 bytes, corresponding to
        /// an Ed25519 expanded secret key.
        ///
        /// Returns an array of 64 bytes, with the first 32 bytes being
        /// the secret scalar shifted ed25519 style, and the last 32 bytes
        /// being the seed for nonces.
        /// https://github.com/w3f/schnorrkel/blob/master/src/keys.rs#L488
        /// </summary>
        /// <returns></returns>
        public byte[] ToEd25519Bytes()
        {
            byte[] bytes = new byte[64];

            byte[] copy = new byte[key.ScalarBytes.Length];
            Array.Copy(key.ScalarBytes, copy, key.ScalarBytes.Length);

            var res = Scalar.MultiplyScalarBytesByCofactor(copy);

            Array.Copy(res, 0, bytes, 0, 32);
            Array.Copy(nonce, 0, bytes, 32, nonce.Length);

            return bytes;
        }

        /// <summary>
        /// Construct an `SecretKey` from a slice of bytes, corresponding to an Ed25519 expanded secret key.
        /// https://github.com/w3f/schnorrkel/blob/master/src/keys.rs#L523
        /// This is exactly the same implementation as FromBytes011, but I prefer to add a new method to keep name consistency
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        internal static SecretKey FromEd25519Bytes(byte[] data) => FromBytes011(data);

        /// <summary>
        /// Vaguely BIP32-like "hard" derivation of a `MiniSecretKey` from a `SecretKey`
        ///
        /// We do not envision any "good reasons" why these "hard"
        /// derivations should ever be used after the soft `Derivation`
        /// trait.  We similarly do not believe hard derivations
        /// make any sense for `ChainCode`s or `ExtendedKey`s types.
        /// Yet, some existing BIP32 workflows might do these things,
        /// due to BIP32's de facto stnadardization and poor design.
        /// In consequence, we provide this method to do "hard" derivations
        /// in a way that should work with all BIP32 workflows and any
        /// permissible mutations of `SecretKey`.  This means only that
        /// we hash the `SecretKey`'s scalar, but not its nonce becuase
        /// the secret key remains valid if the nonce is changed.
        /// 
        /// https://github.com/w3f/schnorrkel/blob/master/src/derive.rs#L118
        /// </summary>
        /// <param name="chainCode"></param>
        /// <returns></returns>
        public (MiniSecret miniSecret, byte[] chainCode) HardDerive(byte[] chainCode)
        {
            var transcript = new Transcript("SchnorrRistrettoHDKD");

            transcript.AppendMessage("sign-bytes", string.Empty);
            transcript.AppendMessage("chain-code", chainCode);
            transcript.AppendMessage("secret-key", this.key.ScalarBytes);

            var msk = new byte[32];
            transcript.ChallengeBytes(System.Text.Encoding.UTF8.GetBytes("HDKD-hard"), ref msk);

            var chainCodeFinal = new byte[32];
            transcript.ChallengeBytes(System.Text.Encoding.UTF8.GetBytes("HDKD-chaincode"), ref chainCodeFinal);

            return (new MiniSecret(msk, ExpandMode.Ed25519), chainCodeFinal);
        }
    }
}