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
    /// A `ProjectivePoint` is a point \\((X:Y:Z)\\) on the \\(\mathbb
    /// P\^2\\) model of the curve.
    /// A point \\((x,y)\\) in the affine model corresponds to
    /// \\((x:y:1)\\).
    ///
    /// More details on the relationships between the different curve models
    /// can be found in the module-level documentation.
    /// </summary>
    public class ProjectivePoint
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
        /// 
        /// </summary>
        /// <returns></returns>
        public CompletedPoint Double()
        {
            var XX = X.Square();
            var YY = Y.Square();
            var ZZ2 = Z.Square2();
            var X_plus_Y = X.Add(Y);
            var X_plus_Y_sq = X_plus_Y.Square();
            var YY_plus_XX = YY.Add(XX);
            var YY_minus_XX = YY.Sub(XX);

            return new CompletedPoint
            {
                X = X_plus_Y_sq.Sub(YY_plus_XX),
                Y = YY_plus_XX,
                Z = YY_minus_XX,
                T = ZZ2.Sub(YY_minus_XX)
            };
        }

        /// <summary>
        /// Return identity
        /// </summary>
        /// <returns></returns>
        internal static ProjectivePoint Identity()
        {
            return new ProjectivePoint
            {
                X = FieldElement51.Zero(),
                Y = FieldElement51.One(),
                Z = FieldElement51.One()
            };
        }

        /// <summary>
        /// Convert this point from the \\( \mathbb P\^2 \\) model to the
        /// \\( \mathbb P\^3 \\) model.
        ///
        /// This costs \\(3 \mathrm M + 1 \mathrm S\\).
        /// </summary>
        /// <returns></returns>
        internal EdwardsPoint ToExtended()
        {
            return new EdwardsPoint
            {
                X = X * Z,
                Y = Y * Z,
                Z = Z.Square(),
                T = X * Y
            };
        }
    }
}