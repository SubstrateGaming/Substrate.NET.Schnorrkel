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
using System;
using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;

namespace Substrate.NET.Schnorrkel.Keys
{
    /// <summary>
    /// An EdDSA-like "secret" key seed.
    ///
    /// These are seeds from which we produce a real `SecretKey`, which
    /// EdDSA itself calls an extended secret key by hashing.  We require
    /// homomorphic properties unavailable from these seeds, so we renamed
    /// these and reserve `SecretKey` for what EdDSA calls an extended
    /// secret key.
    /// </summary>
    public class MiniSecret
    {
        private Scalar secret;
        private byte[] nonce;

        /// <summary>
        /// Instanciate a new MiniSecret
        /// </summary>
        /// <param name="miniKey"></param>
        /// <param name="expandMode"></param>
        /// <exception cref="InvalidEnumArgumentException"></exception>
        public MiniSecret(byte[] miniKey, ExpandMode expandMode)
        {
            switch (expandMode)
            {
                case ExpandMode.Uniform:
                    {
                        ExpandUniform(miniKey);
                        break;
                    }
                case ExpandMode.Ed25519:
                    {
                        ExpandEd25519(miniKey);
                        break;
                    }
                default:
                    {
                        throw new InvalidEnumArgumentException(nameof(expandMode), (int)expandMode, typeof(ExpandMode));
                    }
            }
        }

        /// <summary>
        /// Derive the `Keypair` corresponding to this `MiniSecret`.
        /// </summary>
        /// <returns></returns>
        public KeyPair GetPair()
        {
            return new KeyPair(ExpandToPublic(),
                new SecretKey
                {
                    key = secret,
                    nonce = nonce
                });
        }

        /// <summary>
        /// Create a new SecretKey from this MiniSecret
        /// </summary>
        /// <returns></returns>
        public SecretKey ExpandToSecret()
        {
            return new SecretKey
            {
                key = secret,
                nonce = nonce
            };
        }

        /// <summary>
        /// Derive the `PublicKey` corresponding to this `MiniSecret`.
        /// </summary>
        /// <returns></returns>
        public PublicKey ExpandToPublic()
        {
            var tbl = new RistrettoBasepointTable();
            var R = tbl.Mul(secret).Compress();

            return new PublicKey(R.ToBytes());
        }

        /// <summary>
        /// Expand this `MiniSecret` into a `SecretKey`
        ///
        /// We preoduce a secret keys using merlin and more uniformly
        /// with this method, which reduces binary size and benefits
        /// some future protocols.
        /// </summary>
        /// <param name="miniKey"></param>
        private void ExpandUniform(byte[] miniKey)
        {
            Transcript ts = new Transcript("ExpandSecretKeys");
            ts.AppendMessage("mini", miniKey);

            var scalar_bytes = new byte[64];
            ts.ChallengeBytes(Encoding.UTF8.GetBytes("sk"), ref scalar_bytes);

            secret = Scalar.FromBytesModOrderWide(scalar_bytes);

            nonce = new byte[32];
            ts.ChallengeBytes(Encoding.UTF8.GetBytes("no"), ref nonce);
        }

        /// <summary>
        /// Expand this `MiniSecret` into a `SecretKey` using
        /// ed25519-style bit clamping.
        ///
        /// At present, there is no exposed mapping from Ristretto
        /// to the underlying Edwards curve because Ristretto invovles
        /// an inverse square root, and thus two such mappings exist.
        /// Ristretto could be made usable with Ed25519 keys by choosing
        /// one mapping as standard, but doing so makes the standard more
        /// complex, and possibly harder to implement.  If anyone does
        /// standardize the mapping to the curve then this method permits
        /// compatable schnorrkel and ed25519 keys.
        /// </summary>
        /// <param name="miniKey"></param>
        private void ExpandEd25519(byte[] miniKey)
        {
            SHA512 shaM = new SHA512Managed();
            var shaHash = shaM.ComputeHash(miniKey);

            // We need not clamp in a Schnorr group like Ristretto, but here
            // we do so to improve Ed25519 comparability.
            var key = shaHash.AsMemory().Slice(0, 32).ToArray();
            nonce = shaHash.AsMemory().Slice(32, 32).ToArray();
            key[0] &= 248;
            key[31] &= 63;
            key[31] |= 64;

            // We then divide by the cofactor to internally keep a clean
            // representation mod l.
            Scalar.DivideScalarBytesByCofactor(ref key);
            secret = Scalar.FromBits(key);
        }
    }

    /// <summary>
    /// Methods for expanding a `MiniSecretKey` into a `SecretKey`.
    ///
    /// Our `SecretKey`s consist of a scalar and nonce seed, both 32 bytes,
    /// what EdDSA/Ed25519 calls an extended secret key.  We normally create 
    /// `SecretKey`s by expanding a `MiniSecretKey`, what Esd25519 calls
    /// a `SecretKey`.  We provide two such methods, our suggested approach
    /// produces uniformly distribted secret key scalars, but another
    /// approach retains the bit clamping form Ed25519.
    /// </summary>
    public enum ExpandMode
    {
        /// <summary>
        /// Expand the `MiniSecretKey` into a uniformly distributed
        /// `SecretKey`. 
        ///
        /// We preoduce the `SecretKey` using merlin and far more uniform
        /// sampling, which might benefits some future protocols, and
        /// might reduce binary size if used throughout.  
        ///
        /// We slightly prefer this method, but some existing code uses
        /// `Ed25519` mode, so users cannot necessarily use this mode
        /// if they require compatability with existing systems.
        /// </summary>
        Uniform,

        /// <summary>
        /// Expand this `MiniSecretKey` into a `SecretKey` using
        /// ed25519-style bit clamping.
        ///
        /// Ristretto points are represented by Ed25519 points internally
        /// so concievably some future standard might expose a mapping
        /// from Ristretto to Ed25519, which makes this mode useful.
        /// At present, there is no such exposed mapping however because
        /// two such mappings actually exist, depending upon the branch of
        /// the inverse square root chosen by a Ristretto implementation.
        /// There is however a concern that such a mapping would remain
        /// a second class citizen, meaning implementations differ and
        /// create incompatability.
        ///
        /// We weakly recommend against emoloying this method.  We include
        /// it primarily because early Ristretto documentation touted the 
        /// relationship with Ed25519, which led to some deployments adopting
        /// this expansion method.
        /// </summary>
        Ed25519
    }
}