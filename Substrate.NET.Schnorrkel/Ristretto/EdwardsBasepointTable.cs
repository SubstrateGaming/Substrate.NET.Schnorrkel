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
    /// A precomputed table of multiples of a basepoint, for accelerating
    /// fixed-base scalar multiplication.  One table, for the Ed25519
    /// basepoint, is provided in the `constants` module.
    ///
    /// The basepoint tables are reasonably large (30KB), so they should
    /// probably be boxed.
    /// </summary>
    public class EdwardsBasepointTable
    {
        /// <summary>
        /// Associated EdwardsPoints array
        /// </summary>
        public LookupTable[] lt;

        /// <summary>
        /// The computation uses Pippeneger's algorithm, as described on
        /// page 13 of the Ed25519 paper.  Write the scalar \\(a\\) in radix \\(16\\) with
        /// coefficients in \\([-8,8)\\)
        ///
        /// The radix-\\(16\\) representation requires that the scalar is bounded
        /// by \\(2\^{255}\\), which is always the case.
        /// </summary>
        /// <param name="sclr"></param>
        /// <returns></returns>
        public EdwardsPoint Mul(Scalar sclr)
        {
            var a = sclr.ToRadix16();
            var P = EdwardsPoint.Identity();

            for (var i = 0; i < 64; i++)
            {
                if (i % 2 == 1)
                {
                    var s1 = lt[i / 2].Select(a[i]);
                    var s2 = P.Add(s1);
                    var s3 = s2.ToExtended();

                    P = s3;
                }
            }

            P = P.MulByPow2(4);

            for (var i = 0; i < 64; i++)
            {
                if (i % 2 == 0)
                {
                    P = P.Add(lt[i / 2].Select(a[i])).ToExtended();
                }
            }

            return P;
        }

        /// <summary>
        /// A lookup table of precomputed multiples of a point \\(P\\), used to
        /// compute \\( xP \\) for \\( -8 \leq x \leq 8 \\).
        ///
        /// The computation of \\( xP \\) is done in constant time by the `select` function.
        ///
        /// Since `LookupTable` does not implement `Index`, it's more difficult
        /// to accidentally use the table directly.  Unfortunately the table is
        /// only `pub(crate)` so that we can write hardcoded constants, so it's
        /// still technically possible.  It would be nice to prevent direct
        /// access to the table.
        ///
        /// XXX make this generic with respect to table size
        /// </summary>
        public class LookupTable
        {
            /// <summary>
            /// An EdwardsPoint
            /// </summary>
            private EdwardsPoint _ep;

            /// <summary>
            /// Associated AffineNielsPoint points
            /// </summary>
            public AffineNielsPoint[] affineNielsPoints { get; set; }

            /// <summary>
            /// Create a new instance of LookupTable
            /// </summary>
            public LookupTable()
            { }

            /// <summary>
            /// Create a new instance of LookupTable from an EdwardsPoint
            /// </summary>
            /// <param name="ep"></param>
            public LookupTable(EdwardsPoint ep)
            {
                _ep = ep;
                affineNielsPoints = new AffineNielsPoint[8];
                affineNielsPoints[0] = ep.ToAffineNiels();
                for (var j = 0; j < 7; j++)
                {
                    affineNielsPoints[j + 1] = ep.Add(affineNielsPoints[j]).ToExtended().ToAffineNiels();
                }
            }

            /// <summary>
            /// Given \\(-8 \leq x \leq 8\\), return \\(xP\\) in constant time.
            /// </summary>
            /// <param name="x"></param>
            /// <returns></returns>
            public AffineNielsPoint Select(sbyte x)
            {
                // Compute xabs = |x|
                var xmask = x >> 7;
                sbyte xabs = (sbyte)((x + xmask) ^ xmask);

                // Set t = 0 * P = identity
                var t = new AffineNielsPoint();
                for (var i = 1; i < 9; i++)
                {
                    // Copy `points[j-1] == j*P` onto `t` in constant time if `|x| == j`.
                    t.ConditionalAssign(affineNielsPoints[i - 1], xabs == i);
                }

                // Now t == |x| * P.
                byte neg_mask = (byte)(xmask & 1);
                t.ConditionalNegate(neg_mask == 1);
                // Now t == x * P.

                return t;
            }

            /// <summary>
            /// Create a LookupTable from an EdwardsPoint
            /// </summary>
            /// <param name="ep"></param>
            /// <returns></returns>
            public static LookupTable From(EdwardsPoint ep)
            {
                return new LookupTable(ep);
            }
        }
    }
}