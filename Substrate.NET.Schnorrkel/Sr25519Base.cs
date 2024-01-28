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
using System.Text;

namespace Substrate.NET.Schnorrkel
{
    /// <summary>
    /// Schnorrkel implementation for Substrate.
    /// </summary>
    public abstract class Sr25519Base
    {
        /// <summary>
        /// Random generator.
        /// </summary>
        private readonly RandomGenerator _rng;

        /// <summary>
        /// Sr25519 implementation for Substrate.
        /// </summary>
        /// <param name="settings"></param>
        public Sr25519Base(SchnorrkelSettings settings)
        {
            _rng = settings.RandomGenerator;
        }

        /// <summary>
        /// Get bytearray from string. UTF8 encoding.
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        protected static byte[] GetStrBytes(string s)
        {
            return Encoding.UTF8.GetBytes(s);
        }
    }
}