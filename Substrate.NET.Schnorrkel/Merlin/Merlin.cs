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

using StrobeNet;
using Substrate.NET.Schnorrkel.Exceptions;
using System;
using System.IO;
using System.Linq;
using System.Text;

namespace Substrate.NET.Schnorrkel.Merlin
{
    /// A transcript of a public-coin argument.
    ///
    /// The prover's messages are added to the transcript using
    /// [`append_message`](Transcript::append_message), and the verifier's
    /// challenges can be computed using
    /// [`challenge_bytes`](Transcript::challenge_bytes).
    ///
    /// # Creating and using a Merlin transcript
    ///
    /// To create a Merlin transcript, use [`Transcript::new()`].  This
    /// function takes a domain separation label which should be unique to
    /// the application.
    ///
    /// To use the transcript with a Merlin-based proof implementation,
    /// the prover's side creates a Merlin transcript with an
    /// application-specific domain separation label, and passes a 
    /// reference to the transcript to the proving function(s).
    ///
    /// To verify the resulting proof, the verifier creates their own
    /// Merlin transcript using the same domain separation label, then
    /// passes a reference to the verifier's transcript to the
    /// verification function.
    ///
    /// # Implementing proofs using Merlin
    ///
    /// For information on the design of Merlin and how to use it to
    /// implement a proof system, see the documentation at
    /// [merlin.cool](https://merlin.cool), particularly the [Using
    /// Merlin](https://merlin.cool/use/index.html) section. <summary>
    /// A transcript of a public-coin argument.
    /// 
    /// </summary>
    internal class Transcript
    {
        public Strobe _obj { get; private set; }
        private const string MERLIN_PROTOCOL_LABEL = "Merlin v1.0";

        public override string ToString()
        {
            return _obj?.DebugPrintState();
        }

        /// <summary>
        /// Instanciate a new Transcript
        /// </summary>
        /// <param name="obj"></param>
        private Transcript(Strobe obj)
        {
            _obj = obj.Clone() as Strobe;
        }

        /// <summary>
        /// Convert hexa string to a byte array
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        /// <summary>
        /// Initialize a new transcript with the supplied `label`, which is used as a domain separator.
        /// </summary>
        /// <param name="label"></param>
        public Transcript(string label)
        {
            _obj = new Strobe(MERLIN_PROTOCOL_LABEL, 128);
            AppendMessage(Encoding.UTF8.GetBytes("dom-sep"), Encoding.UTF8.GetBytes(label));
        }

        /// <summary>
        /// Initialize a new transcript with the supplied `label`, which is used as a domain separator.
        /// </summary>
        /// <param name="label"></param>
        public Transcript(byte[] label)
        {
            _obj = new Strobe(MERLIN_PROTOCOL_LABEL, 128);
            AppendMessage(Encoding.UTF8.GetBytes("dom-sep"), label);
        }

        /// <summary>
        /// Clone the transcript instance
        /// </summary>
        /// <returns></returns>
        public Transcript Clone()
        {
            return new Transcript((Strobe)_obj.Clone());
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private byte[] EncodeU64(byte[] data)
        {
            byte[] result;
            using (Stream dataStream = new MemoryStream(data, false))
            {
                using (MemoryStream stream = new MemoryStream())
                {
                    using (StreamWriter sr = new StreamWriter(stream, Encoding.BigEndianUnicode))
                    {
                        while (dataStream.CanRead)
                        {
                            var major = dataStream.ReadByte();
                            var minor = dataStream.ReadByte();

                            sr.Write(minor + major);
                        }

                        result = stream.ToArray();
                    }
                }
            }

            return result;
        }

        public void MetaAd(byte[] data, bool more)
        {
            var error = _obj.Operate(true, StrobeNet.Enums.Operation.Ad, data, 0, more);
            if (error != null)
            {
                throw new TranscriptException($"{error}");
            }
        }

        public void Ad(byte[] data, bool more)
        {
            var error = _obj.Operate(false, StrobeNet.Enums.Operation.Ad, data, 0, more);
            if (error != null)
            {
                throw new TranscriptException($"{error}");
            }
        }

        public byte[] Prf(int expectedOutput, bool more)
        {
            var result = _obj.Operate(false, StrobeNet.Enums.Operation.Prf, null, expectedOutput, more);
            if (result == null)
            {
                throw new TranscriptException($"{result}");
            }

            return result;
        }

        public void Key(byte[] data, bool more)
        {
            var error = _obj.Operate(false, StrobeNet.Enums.Operation.Key, data, 0, more);
            if (error != null)
            {
                throw new TranscriptException($"{error}");
            }
        }

        public Strobe TranscriptCommit(string sth, byte[] message)
        {
            var obj = new Strobe("Merlin", 128);
            obj.Ad(true, message);
            return obj;
        }

        /// <summary>
        /// Append a prover's `message` to the transcript.
        ///
        /// The `label` parameter is metadata about the message, and is
        /// also appended to the transcript.  See the [Transcript
        /// Protocols](https://merlin.cool/use/protocol.html) section of
        /// the Merlin website for details on labels.
        /// </summary>
        /// <param name="label"></param>
        /// <param name="message"></param>
        public void AppendMessage(string label, string message)
        {
            AppendMessage(Encoding.UTF8.GetBytes(label), Encoding.UTF8.GetBytes(message));
        }

        /// <summary>
        /// Append a prover's `message` to the transcript.
        ///
        /// The `label` parameter is metadata about the message, and is
        /// also appended to the transcript.  See the [Transcript
        /// Protocols](https://merlin.cool/use/protocol.html) section of
        /// the Merlin website for details on labels.
        /// </summary>
        /// <param name="label"></param>
        /// <param name="message"></param>
        public void AppendMessage(string label, byte[] message)
        {
            AppendMessage(Encoding.UTF8.GetBytes(label), message);
        }

        /// <summary>
        /// Append a prover's `message` to the transcript.
        ///
        /// The `label` parameter is metadata about the message, and is
        /// also appended to the transcript.  See the [Transcript
        /// Protocols](https://merlin.cool/use/protocol.html) section of
        /// the Merlin website for details on labels.
        /// </summary>
        /// <param name="label"></param>
        /// <param name="message"></param>
        public void AppendMessage(byte[] label, string message)
        {
            AppendMessage(label, Encoding.UTF8.GetBytes(message));
        }

        /// <summary>
        /// Append a prover's `message` to the transcript.
        ///
        /// The `label` parameter is metadata about the message, and is
        /// also appended to the transcript.  See the [Transcript
        /// Protocols](https://merlin.cool/use/protocol.html) section of
        /// the Merlin website for details on labels.
        /// </summary>
        /// <param name="label"></param>
        /// <param name="message"></param>
        public void AppendMessage(byte[] label, byte[] message)
        {
            // var dataLength = message.Length;

            MetaAd(label, false);
            MetaAd(BitConverter.GetBytes(message.Length), true);
            Ad(message, false);
        }

        /// <summary>
        /// This function was renamed to
        /// [`append_message`](Transcript::append_message).
        ///
        /// This is intended to avoid any possible confusion between the
        /// transcript-level messages and protocol-level commitments.
        /// </summary>
        /// <param name="label"></param>
        /// <param name="message"></param>
        [Obsolete("Rename to AppendMessage")]
        public void CommitBytes(byte[] label, byte[] message)
        {
            AppendMessage(label, message);
        }

        /// <summary>
        /// Convenience method for appending a `u64` to the transcript.
        ///
        /// The `label` parameter is metadata about the message, and is
        /// also appended to the transcript.  See the [Transcript
        /// Protocols](https://merlin.cool/use/protocol.html) section of
        /// the Merlin website for details on labels.
        /// </summary>
        /// <param name="label"></param>
        /// <param name="message"></param>
        public void AppendU64(byte[] label, byte[] message)
        {
            AppendMessage(label, EncodeU64(message));
        }

        /// <summary>
        /// This function was renamed to
        /// [`append_u64`](Transcript::append_u64).
        ///
        /// This is intended to avoid any possible confusion between the
        /// transcript-level messages and protocol-level commitments.
        /// </summary>
        /// <param name="label"></param>
        /// <param name="message"></param>
        [Obsolete("Rename to AppendU64")]
        public void CommitU64(byte[] label, byte[] message)
        {
            AppendU64(label, message);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="dest"></param>
        /// <param name="nonceSeeds"></param>
        /// <param name="rng"></param>
        public void WitnessBytes(ref byte[] dest, byte[] nonceSeeds, RandomGenerator rng)
        {
            byte[][] ns = new byte[][] { nonceSeeds };
            WitnessBytesRng(ref dest, ns, rng);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="label"></param>
        /// <param name="dest"></param>
        /// <param name="nonceSeeds"></param>
        /// <param name="rng"></param>
        public void WitnessBytes(byte[] label, ref byte[] dest, byte[] nonceSeeds, RandomGenerator rng)
        {
            byte[][] ns = new byte[][] { nonceSeeds };
            WitnessBytesRng(label, ref dest, ns, rng);
        }

        /// <summary>
        /// Fill the supplied buffer with the verifier's challenge bytes.
        ///
        /// The `label` parameter is metadata about the challenge, and is
        /// also appended to the transcript.  See the [Transcript
        /// Protocols](https://merlin.cool/use/protocol.html) section of
        /// the Merlin website for details on labels.
        /// </summary>
        /// <param name="label"></param>
        /// <param name="buffer"></param>
        public void ChallengeBytes(byte[] label, ref byte[] buffer)
        {
            MetaAd(label, false);
            MetaAd(BitConverter.GetBytes(buffer.Length), true);

            buffer = Prf(buffer.Length, false);
        }

        /// <summary>
        /// Fork the current [`Transcript`] to construct an RNG whose output is bound
        /// to the current transcript state as well as prover's secrets.
        /// </summary>
        /// <returns></returns>
        public TranscriptRngBuilder BuildRng()
        {
            return new TranscriptRngBuilder(Clone());
        }

        public void WitnessBytesRng(byte[] label, ref byte[] dest, byte[][] nonce_seeds, RandomGenerator rng)
        {
            var br = BuildRng();
            foreach (var ns in nonce_seeds)
            {
                br = br.RekeyWithWitnessBytes(label, ns);
            }
            var r = br.Finalize(rng);
            r.FillBytes(ref dest);
        }

        public void WitnessBytesRng(ref byte[] dest, byte[][] nonce_seeds, RandomGenerator rng)
        {
            //let mut br = self.build_rng();
            //for ns in nonce_seeds {
            //    br = br.commit_witness_bytes(b"", ns);
            //}
            //let mut r = br.finalize(&mut rng);
            //r.fill_bytes(dest)

            var br = BuildRng();
            var emptyLabel = new byte[] { };
            foreach (var ns in nonce_seeds)
            {
                br = br.RekeyWithWitnessBytes(emptyLabel, ns);
            }
            var r = br.Finalize(rng);
            r.FillBytes(ref dest);
        }
    }

    /// <summary>
    /// Constructs a [`TranscriptRng`] by rekeying the [`Transcript`] with prover secrets and an external RNG.
    /// </summary>
    internal class TranscriptRngBuilder
    {
        public Transcript _strobe { get; private set; }

        public TranscriptRngBuilder(Transcript strobe)
        {
            _strobe = strobe;
        }

        /// <summary>
        /// Rekey the transcript using the provided witness data.
        ///
        /// The `label` parameter is metadata about `witness`.
        /// </summary>
        /// <param name="label"></param>
        /// <param name="witness"></param>
        /// <returns></returns>
        public TranscriptRngBuilder RekeyWithWitnessBytes(byte[] label, byte[] witness)
        {
            _strobe.MetaAd(label, false);
            _strobe.MetaAd(BitConverter.GetBytes(witness.Length), true);
            _strobe.Key(witness, false);

            return this;
        }

        /// <summary>
        /// Use the supplied external `rng` to rekey the transcript, so
        /// that the finalized [`TranscriptRng`] is a PRF bound to
        /// randomness from the external RNG, as well as all other
        /// transcript data.
        /// </summary>
        /// <param name="rng"></param>
        /// <returns></returns>
        public TranscriptRng Finalize(RandomGenerator rng)
        {
            var bytes = new byte[32];
            bytes.Initialize();
            rng.FillBytes(ref bytes);

            _strobe.MetaAd(Encoding.UTF8.GetBytes("rng"), false);
            _strobe.Key(bytes, false);

            return new TranscriptRng(_strobe);
        }
    }

    /// <summary>
    /// Abstract class for implementing random byte generator
    /// </summary>
    public abstract class RandomGenerator
    {
        /// <summary>
        /// Generate bytes
        /// </summary>
        /// <param name="dst"></param>
        public abstract void FillBytes(ref byte[] dst);
    }

    /// <summary>
    /// Constructs a [`TranscriptRng`] by rekeying the [`Transcript`] with
    /// prover secrets and an external RNG.
    /// </summary>
    internal class TranscriptRng : RandomGenerator
    {
        private static Random _rnd;
        public Transcript _strobe { get; private set; }
        private byte[] _strobeBytes;
        private int _pointer;

        /// <summary>
        /// Instanciate a new TranscriptRng
        /// </summary>
        /// <param name="strobe"></param>
        public TranscriptRng(Transcript strobe)
        {
            if (_rnd == null)
            {
                _rnd = new Random();
            }

            _strobe = strobe;
            _strobeBytes = Transcript.StringToByteArray(strobe._obj.DebugPrintState());
            _pointer = 0;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="dst"></param>
        public override void FillBytes(ref byte[] dst)
        {
            _strobe.MetaAd(BitConverter.GetBytes(dst.Length), false);
            dst = _strobe.Prf(dst.Length, false);
        }
    }
}