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
using Substrate.NET.Schnorrkel.Scalars;
using System;
using System.Text;

namespace Substrate.NET.Schnorrkel.Keys
{
    public class KeyPair
    {
        public PublicKey Public { get; set; }
        public SecretKey Secret { get; set; }

        public KeyPair(PublicKey publicKey, SecretKey secretKey)
        {
            this.Public = publicKey;
            this.Secret = secretKey;
        }

        /// <summary>
        /// https://github.com/w3f/schnorrkel/blob/master/src/keys.rs#L823
        /// </summary>
        /// <returns></returns>
        public byte[] ToHalfEd25519Bytes()
        {
            byte[] bytes = new byte[96];

            byte[] secretBytes = Secret.ToEd25519Bytes();
            Array.Copy(secretBytes, 0, bytes, 0, 64);

            byte[] publicBytes = Public.Key;
            Array.Copy(publicBytes, 0, bytes, 64, publicBytes.Length);

            return bytes;
        }

        /// <summary>
        /// https://github.com/w3f/schnorrkel/blob/master/src/keys.rs#L853
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public static KeyPair FromHalfEd25519Bytes(byte[] data)
        {
            if (data.Length != 96)
                throw new ArgumentException("Invalid KeyPair bytes parameters");

            byte[] secretKey = new byte[64];
            Array.Copy(data, 0, secretKey, 0, 64);

            var privateKey = SecretKey.FromEd25519Bytes(secretKey);

            var publicKey = new byte[32];
            Array.Copy(data, 64, publicKey, 0, 32);

            return new KeyPair(new PublicKey(publicKey), privateKey);
        }

        /// <summary>
        /// https://github.com/w3f/schnorrkel/blob/master/src/derive.rs#L63 + https://github.com/w3f/schnorrkel/blob/master/src/derive.rs#L181
        /// </summary>
        /// <param name="chainCode"></param>
        /// <returns></returns>
        public (KeyPair keyPair, byte[] chainCode) SoftDerive(byte[] chainCode)
        {
            var transcript = new Transcript("SchnorrRistrettoHDKD");
            transcript.AppendMessage("sign-bytes", string.Empty);

            var (scalarDerive, ccDerive) = Public.DeriveScalarAndChainCode(transcript, chainCode);

            var combinedBytes = new System.Collections.Generic.List<byte>(Secret.nonce.Length + Secret.key.ScalarBytes.Length);
            combinedBytes.AddRange(Secret.nonce);
            combinedBytes.AddRange(Secret.key.ScalarBytes);
            var calcNonce = new byte[32];
            transcript.WitnessBytes(Encoding.UTF8.GetBytes("HDKD-nonce"), ref calcNonce, combinedBytes.ToArray(), new Simple());

            Secret.key.Recalc();
            var addScalar = new Scalar { ScalarBytes = (Secret.key.ScalarInner + scalarDerive.ScalarInner).ToBytes() };
            addScalar.Recalc();

            var secretKey = new SecretKey()
            {
                key = addScalar,
                nonce = calcNonce
            };

            return (new KeyPair(secretKey.ExpandToPublic(), secretKey), ccDerive);
        }
    }
}