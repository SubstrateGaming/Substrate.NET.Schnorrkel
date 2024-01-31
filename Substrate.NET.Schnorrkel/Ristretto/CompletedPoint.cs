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

using Substrate.NET.Schnorrkel.Scalars;

namespace Substrate.NET.Schnorrkel.Ristretto
{
    /// <summary>
    /// A `CompletedPoint` is a point \\(((X:Z), (Y:T))\\) on the \\(\mathbb
    /// P\^1 \times \mathbb P\^1 \\) model of the curve.
    /// A point (x,y) in the affine model corresponds to \\( ((x:1),(y:1))
    /// \\).
    ///
    /// More details on the relationships between the different curve models
    /// can be found in the module-level documentation.
    /// </summary>
    public class CompletedPoint
    {
        /// <summary>
        /// X field
        /// </summary>
        public FieldElement51 X { get; set; }

        /// <summary>
        /// Y field
        /// </summary>
        public FieldElement51 Y { get; set; }

        /// <summary>
        /// Z field
        /// </summary>
        public FieldElement51 Z { get; set; }

        /// <summary>
        /// T field
        /// </summary>
        public FieldElement51 T { get; set; }

        /// <summary>
        /// Convert this point from the \\( \mathbb P\^1 \times \mathbb P\^1
        /// \\) model to the \\( \mathbb P\^2 \\) model.
        ///
        /// This costs \\(3 \mathrm M \\).
        /// </summary>
        /// <returns></returns>
        public ProjectivePoint ToProjective()
        {
            return new ProjectivePoint
            {
                X = X.Mul(T),
                Y = Y.Mul(Z),
                Z = Z.Mul(T)
            };
        }

        /// <summary>
        /// Convert this point from the \\( \mathbb P\^1 \times \mathbb P\^1
        /// \\) model to the \\( \mathbb P\^3 \\) model.
        ///
        /// This costs \\(4 \mathrm M \\).
        /// </summary>
        /// <returns></returns>
        public EdwardsPoint ToExtended()
        {
            return new EdwardsPoint
            {
                X = X.Mul(T),
                Y = Y.Mul(Z),
                Z = Z.Mul(T),
                T = X.Mul(Y)
            };
        }
    }
}