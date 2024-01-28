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
using Substrate.NET.Schnorrkel.Ristretto;
using Substrate.NET.Schnorrkel.Scalars;
using System;

namespace Substrate.NET.Schnorrkel.Signed
{
    /// <summary>
    /// A Ristretto Schnorr signature "detached" from the signed message.
    /// </summary>
    public struct Signature
    {
        /// <summary>
        /// `R` is a `RistrettoPoint`, formed by using an hash function with
        /// 512-bits output to produce the digest of:
        ///
        /// - the nonce half of the `SecretKey`, and
        /// - the message to be signed.
        ///
        /// This digest is then interpreted as a `Scalar` and reduced into an
        /// element in ℤ/lℤ.  The scalar is then multiplied by the distinguished
        /// basepoint to produce `R`, and `RistrettoPoint`.
        /// </summary>
        public CompressedRistretto R { get; set; }

        /// <summary>
        /// `s` is a `Scalar`, formed by using an hash function with 512-bits output
        /// to produce the digest of:
        ///
        /// - the `r` portion of this `Signature`,
        /// - the `PublicKey` which should be used to verify this `Signature`, and
        /// - the message to be signed.
        ///
        /// This digest is then interpreted as a `Scalar` and reduced into an
        /// element in ℤ/lℤ.
        /// </summary>
        public Scalar S { get; set; }

        public void FromBytes011(byte[] signatureBytes)
        {
            var r = new CompressedRistretto(signatureBytes.AsMemory(0, 32).ToArray());
            var s = new Scalar();
            s.ScalarBytes = new byte[32];
            signatureBytes.AsMemory(32, 32).CopyTo(s.ScalarBytes);
            s.Recalc();

            R = r;
            S = s;
        }

        public byte[] ToBytes011()
        {
            var bytes = new byte[Consts.SIGNATURE_LENGTH];
            R.ToBytes().AsMemory().CopyTo(bytes.AsMemory(0, 32));
            S.ScalarBytes.AsMemory().CopyTo(bytes.AsMemory(32, 32));
            return bytes;
        }

        /// <summary>
        /// Construct a `Signature` from a slice of bytes.
        ///
        /// We distinguish schnorrkell signatures from ed25519 signatures
        /// by setting the high bit of byte 31.  We return an error if
        /// this marker remains unset because otherwise schnorrkel 
        /// signatures would be indistinguishable from ed25519 signatures.
        /// We cannot always distinguish between schnorrkel and ed25519
        /// public keys either, so without this market bit we could not
        /// do batch verification in systems that support precisely
        /// ed25519 and schnorrkel.  
        ///
        /// We cannot distinguish amongst different `SigningTranscript`
        /// types using these markey bits, but protocol should not need
        /// two different transcript types.
        /// </summary>
        /// <param name="signatureBytes"></param>
        /// <exception cref="Exception"></exception>
        public void FromBytes(byte[] signatureBytes)
        {
            byte[] clonedSignature = new byte[signatureBytes.Length];
            Array.Copy(signatureBytes, clonedSignature, signatureBytes.Length);

            if ((clonedSignature[63] & 128) == 0)
            {
                throw new SignatureException("Signature bytes not marked as a schnorrkel signature");
            }

            // remove schnorrkel signature mark
            clonedSignature[63] &= 127;
            var r = new CompressedRistretto(clonedSignature.AsMemory(0, 32).ToArray());
            var s = new Scalar();
            s.ScalarBytes = new byte[32];
            clonedSignature.AsMemory(32, 32).CopyTo(s.ScalarBytes);
            s.Recalc();

            R = r;
            S = s;
        }

        /// <summary>
        /// Convert this `Signature` to a byte array.
        /// </summary>
        /// <returns></returns>
        public byte[] ToBytes()
        {
            var bytes = new byte[Consts.SIGNATURE_LENGTH];
            R.ToBytes().AsMemory().CopyTo(bytes.AsMemory(0, 32));
            S.ScalarBytes.AsMemory().CopyTo(bytes.AsMemory(32, 32));

            // Add schnorrkel signature mark
            bytes[63] |= 128;
            return bytes;
        }
    }
}