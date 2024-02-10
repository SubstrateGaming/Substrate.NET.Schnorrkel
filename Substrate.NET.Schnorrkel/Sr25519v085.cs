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

using Substrate.NET.Schnorrkel.Merlin;
using Substrate.NET.Schnorrkel.Ristretto;
using Substrate.NET.Schnorrkel.Scalars;
using Substrate.NET.Schnorrkel.Signed;
using System;
using System.Text;

namespace Substrate.NET.Schnorrkel
{
    /// <summary>
    /// Schnorrkel implementation for Substrate.
    /// </summary>
    public class Sr25519v085 : Sr25519Base
    {
        /// <summary>
        /// Create a new instance of Sr25519.
        /// </summary>
        /// <param name="settings"></param>
        public Sr25519v085(SchnorrkelSettings settings) : base(settings)
        {
        }

        /// <summary>
        /// Sign a message with a given public and secret key.
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="secretKey"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        [Obsolete("Use SignSimpleFromEd25519 instead")]
        internal static byte[] SignSimple(byte[] publicKey, byte[] secretKey, byte[] message)
        {
            var sk = SecretKey.FromBytes085(secretKey);
            var pk = new PublicKey(publicKey);
            var signingContext = new SigningContext085(Encoding.UTF8.GetBytes("substrate"));
            var st = new SigningTranscript(signingContext);
            signingContext.ts = signingContext.Bytes(message);

            var rng = new Simple();
            // var rng = new Hardcoded();

            var sig = Sign(st, sk, pk, rng);

            return sig.ToBytes();
        }

        /// <summary>
        /// Sign from Secret key from Ed25519 bytes (need to DivideScalarBytesByCofactor)
        /// </summary>
        /// <param name="publicKey"></param>
        /// <param name="secretKey"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        public static byte[] SignSimpleFromEd25519(byte[] publicKey, byte[] secretKey, byte[] message)
        {
            var sk = SecretKey.FromEd25519Bytes(secretKey);
            var pk = new PublicKey(publicKey);
            var signingContext = new SigningContext085(Encoding.UTF8.GetBytes("substrate"));
            var st = new SigningTranscript(signingContext);
            signingContext.ts = signingContext.Bytes(message);
            var rng = new Simple();
            var sig = Sign(st, sk, pk, rng);

            return sig.ToBytes();
        }

        /// <summary>
        /// Sign a message with a given public and secret key.
        /// </summary>
        /// <param name="st"></param>
        /// <param name="secretKey"></param>
        /// <param name="publicKey"></param>
        /// <param name="rng"></param>
        /// <returns></returns>
        internal static Signature Sign(SigningTranscript st, SecretKey secretKey, PublicKey publicKey, RandomGenerator rng)
        {
            st.SetProtocolName(GetStrBytes("Schnorr-sig"));
            st.CommitPoint(GetStrBytes("sign:pk"), publicKey.Key);

            var r = st.WitnessScalar(GetStrBytes("signing"), secretKey.nonce, rng);

            var tbl = new RistrettoBasepointTable();
            var R = tbl.Mul(r).Compress();

            st.CommitPoint(GetStrBytes("sign:R"), R);

            Scalar k = st.ChallengeScalar(GetStrBytes("sign:c"));  // context, message, A/public_key, R=rG
            k.Recalc();
            secretKey.key.Recalc();
            r.Recalc();

            var scalar = k.ScalarInner * secretKey.key.ScalarInner + r.ScalarInner;

            var s = new Scalar { ScalarBytes = scalar.ToBytes() };
            s.Recalc();

            return new Signature { R = R, S = s };
        }
    }
}