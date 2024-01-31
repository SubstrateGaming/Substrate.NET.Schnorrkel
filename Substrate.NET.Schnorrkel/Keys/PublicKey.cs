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

namespace Substrate.NET.Schnorrkel
{
    /// <summary>
    /// A Ristretto Schnorr public key.
    ///
    /// Internally, these are represented as a `RistrettoPoint`, meaning
    /// an Edwards point with a static guarantee to be 2-torsion free.
    ///
    /// At present, we decompress `PublicKey`s into this representation
    /// during deserialization, which improves error handling, but costs
    /// a compression during signing and verifiaction.
    /// </summary>
    public class PublicKey
    {
        /// <summary>
        /// The public key
        /// </summary>
        public byte[] Key { get; }

        /// <summary>
        /// Create a new public key from byte array
        /// </summary>
        /// <param name="keyBytes"></param>
        public PublicKey(byte[] keyBytes)
        {
            Key = keyBytes;
        }

        internal EdwardsPoint GetEdwardsPoint()
        {
            return EdwardsPoint.Decompress(Key);
        }

        /// <summary>
        /// https://github.com/w3f/schnorrkel/blob/master/src/derive.rs#L89
        /// </summary>
        /// <param name="transcript"></param>
        /// <param name="chainCode"></param>
        /// <returns></returns>
        internal (Scalar, byte[]) DeriveScalarAndChainCode(Transcript transcript, byte[] chainCode)
        {
            transcript.CommitBytes(System.Text.Encoding.UTF8.GetBytes("chain-code"), chainCode);
            transcript.CommitBytes(System.Text.Encoding.UTF8.GetBytes("public-key"), Key);

            var scalar64 = new byte[64];
            transcript.ChallengeBytes(System.Text.Encoding.UTF8.GetBytes("HDKD-scalar"), ref scalar64);

            var scalar52 = UnpackedScalar.FromBytesWide(scalar64);
            Scalar scalar = UnpackedScalar.Pack(scalar52);

            var chainCodeFinal = new byte[32];
            transcript.ChallengeBytes(System.Text.Encoding.UTF8.GetBytes("HDKD-chaincode"), ref chainCodeFinal);

            return (scalar, chainCodeFinal);
        }
    }
}