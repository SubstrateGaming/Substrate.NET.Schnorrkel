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
    /// A pre-computed point on the \\( \mathbb P\^3 \\) model for the curve, represented as \\((Y+X, Y-X, Z, 2dXY)\\) in "Niels coordinates".
    /// </summary>
    public class ProjectiveNielsPoint
    {
        /// <summary>
        /// Y + X field element equation
        /// </summary>
        public FieldElement51 Y_plus_X { get; set; }

        /// <summary>
        /// Y - X field element equation
        /// </summary>
        public FieldElement51 Y_minus_X { get; set; }

        /// <summary>
        /// Z field element in the equation
        /// </summary>
        public FieldElement51 Z { get; set; }

        /// <summary>
        /// T2d field element in the equation
        /// </summary>
        public FieldElement51 T2d { get; set; }

        /// <summary>
        /// Instanciate a new ProjectiveNielsPoint
        /// </summary>
        public ProjectiveNielsPoint()
        {
            Y_plus_X = new FieldElement51();
            Y_minus_X = new FieldElement51();
            Z = new FieldElement51();
            T2d = new FieldElement51();
        }

        /// <summary>
        /// Logical Xor operator
        /// </summary>
        /// <param name="a"></param>
        /// <returns></returns>
        public ProjectiveNielsPoint BitXor(ProjectiveNielsPoint a)
        {
            return new ProjectiveNielsPoint
            {
                Y_plus_X = Y_plus_X.BitXor(a.Y_plus_X),
                Y_minus_X = Y_minus_X.BitXor(a.Y_minus_X),
                Z = Z.BitXor(a.Z),
                T2d = T2d.BitXor(a.T2d),
            };
        }

        /// <summary>
        /// Logical And operator
        /// </summary>
        /// <param name="a"></param>
        /// <returns></returns>
        public ProjectiveNielsPoint BitAnd(uint a)
        {
            return new ProjectiveNielsPoint
            {
                Y_plus_X = Y_plus_X.BitAnd(a),
                Y_minus_X = Y_minus_X.BitAnd(a),
                Z = Z.BitAnd(a),
                T2d = T2d.BitAnd(a)
            };
        }

        /// <summary>
        /// Invert the sign of this field element
        /// </summary>
        /// <returns></returns>
        public ProjectiveNielsPoint Negate()
        {
            return new ProjectiveNielsPoint
            {
                Y_plus_X = Y_plus_X.Negate(),
                Y_minus_X = Y_minus_X.Negate(),
                Z = Z.Negate(),
                T2d = T2d.Negate()
            };
        }

        /// <summary>
        /// Copy / Clone a ProjectiveNielsPoint
        /// </summary>
        /// <returns></returns>
        public ProjectiveNielsPoint Copy()
        {
            return new ProjectiveNielsPoint
            {
                Y_plus_X = Y_plus_X,
                Y_minus_X = Y_minus_X,
                Z = Z,
                T2d = T2d
            };
        }

        /// <summary>
        /// Return the instance of ProjectiveNielsPoint
        /// </summary>
        /// <returns></returns>
        public ProjectiveNielsPoint GetPoint()
        {
            return this;
        }

        /// <summary>
        /// Create a ProjectiveNielsPoint from a point
        /// </summary>
        /// <param name="a"></param>
        public void FromPoint(ProjectiveNielsPoint a)
        {
            Y_plus_X = a.Y_plus_X;
            Y_minus_X = a.Y_minus_X;
            Z = a.Z;
            T2d = a.T2d;
        }

        /// <summary>
        /// Conditional assign based on `choice`
        /// </summary>
        /// <param name="a"></param>
        /// <param name="choice"></param>
        public void ConditionalAssign(ProjectiveNielsPoint a, bool choice)
        {
            // if choice = 0, mask = (-0) = 0000...0000
            // if choice = 1, mask = (-1) = 1111...1111
            int mask = choice ? 0b1111_1111_1111_1111 : 0b0000_0000_0000_0000;

            //    *self ^= mask & (*self ^ *other);
            FromPoint(GetPoint().BitXor(BitXor(a).BitAnd((uint)mask)));
        }

        /// <summary>
        /// Conditional negate based on `choice`
        /// </summary>
        /// <param name="choice"></param>
        public void ConditionalNegate(bool choice)
        {
            var p = GetPoint();
            ConditionalAssign(p, choice);
        }
    }
}