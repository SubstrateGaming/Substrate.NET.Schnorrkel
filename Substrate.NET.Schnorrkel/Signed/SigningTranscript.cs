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

namespace Substrate.NET.Schnorrkel.Signed
{
    internal class SigningTranscript
    {
        private SigningTranscriptOperation _operations;
        private ISigningContext _context;

        public SigningTranscript(SigningContext085 context)
        {
            _operations = new SigningTranscriptOperation();
            _context = context;
        }

        public SigningTranscript(SigningContext011 context)
        {
            _operations = new SigningTranscriptOperation();
            _context = context;
        }

        public void SetProtocolName(byte[] label)
        {
            _operations.CommitBytes(_context.GetTranscript(), "proto-name", label);
        }

        public void CommitPoint(byte[] label, CompressedRistretto compressed)
        {
            _operations.CommitBytes(_context.GetTranscript(), label, compressed.ToBytes());
        }

        public void CommitPoint(byte[] label, byte[] bytes)
        {
            _operations.CommitBytes(_context.GetTranscript(), label, bytes);
        }

        public Scalar WitnessScalar(byte[] label, byte[] bytes, RandomGenerator rng)
        {
            return _operations.WitnessScalar(_context.GetTranscript(), label, bytes, rng);
        }

        public Scalar WitnessScalar(byte[] bytes, RandomGenerator rng)
        {
            return _operations.WitnessScalar(_context.GetTranscript(), bytes, rng);
        }

        public Scalar ChallengeScalar(byte[] label)
        {
            var data = ChallengeBytes(label);
            return Scalar.FromBytesModOrderWide(data);
        }

        public byte[] ChallengeBytes(byte[] label)
        {
            var result = _operations.ChallengeBytes(_context.GetTranscript(), label);
            return result;
        }
    }

    internal class SigningTranscriptOperation
    {
        public byte[] ChallengeBytes(Transcript ts, byte[] label)
        {
            var buf = new byte[64];
            ts.ChallengeBytes(label, ref buf);
            return buf;
        }

        public void CommitBytes(Transcript ts, byte[] label, byte[] bytes)
        {
            ts.AppendMessage(label, bytes);
        }

        public void CommitBytes(Transcript ts, string label, byte[] bytes)
        {
            ts.AppendMessage(label, bytes);
        }

        public void CommitPoint(Transcript ts, byte[] label, byte[] compressedRistretto)
        {
            CommitBytes(ts, label, compressedRistretto);
        }

        public Scalar WitnessScalar(Transcript ts, byte[] nonce, RandomGenerator rng)
        {
            byte[] bt = new byte[64];
            bt.Initialize();
            ts.WitnessBytes(ref bt, nonce, rng);

            return Scalar.FromBytesModOrderWide(bt);
        }

        public Scalar WitnessScalar(Transcript ts, byte[] label, byte[] nonce, RandomGenerator rng)
        {
            byte[] bt = new byte[64];
            bt.Initialize();
            ts.WitnessBytes(label, ref bt, nonce, rng);

            return Scalar.FromBytesModOrderWide(bt);
        }
    }
}