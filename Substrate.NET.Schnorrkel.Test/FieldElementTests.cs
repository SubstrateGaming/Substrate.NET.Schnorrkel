using NUnit.Framework;
using System.Linq;
using FieldElement51 = Substrate.NET.Schnorrkel.Scalars.FieldElement51;

namespace Substrate.NET.Schnorrkel.Test
{
    public class FieldElementTests
    {
        private readonly byte[] A_BYTES = { 0x04, 0xfe, 0xdf, 0x98, 0xa7, 0xfa, 0x0a, 0x68, 0x84, 0x92, 0xbd, 0x59, 0x08, 0x07, 0xa7, 0x03, 0x9e, 0xd1, 0xf6, 0xf2, 0xe1, 0xd9, 0xe2, 0xa4, 0xa4, 0x51, 0x47, 0x36, 0xf3, 0xc3, 0xa9, 0x17 };
        private readonly byte[] ASQ_BYTES = { 0x75, 0x97, 0x24, 0x9e, 0xe6, 0x06, 0xfe, 0xab, 0x24, 0x04, 0x56, 0x68, 0x07, 0x91, 0x2d, 0x5d, 0x0b, 0x0f, 0x3f, 0x1c, 0xb2, 0x6e, 0xf2, 0xe2, 0x63, 0x9c, 0x12, 0xba, 0x73, 0x0b, 0xe3, 0x62 };
        private readonly byte[] AINV_BYTES = { 0x96, 0x1b, 0xcd, 0x8d, 0x4d, 0x5e, 0xa2, 0x3a, 0xe9, 0x36, 0x37, 0x93, 0xdb, 0x7b, 0x4d, 0x70, 0xb8, 0x0d, 0xc0, 0x55, 0xd0, 0x4c, 0x1d, 0x7b, 0x90, 0x71, 0xd8, 0xe9, 0xb6, 0x18, 0xe6, 0x30 };
        public static readonly byte[] B_BYTES = new byte[]
    {
        113, 191, 169, 143, 91, 234, 121, 15,
        241, 131, 217, 36, 230, 101, 92, 234,
        8, 208, 170, 251, 97, 127, 70, 210,
        58, 23, 166, 87, 240, 169, 184, 178
    };

        public static readonly FieldElement51 SQRT_M1 = new FieldElement51(new ulong[]
    {
        1718705420411056,
        234908883556509,
        2233514472574048,
        2117202627021982,
        765476049583133
    });

        [Test]
        public void AMulAVsASquaredConstant()
        {
            var a = FieldElement51.FromBytes(A_BYTES);
            var asq = FieldElement51.FromBytes(ASQ_BYTES);
            Assert.AreEqual(asq.ToBytes(), (a * a).ToBytes());
        }

        [Test]
        public void ASquareVsASquaredConstant()
        {
            var a = FieldElement51.FromBytes(A_BYTES);
            var asq = FieldElement51.FromBytes(ASQ_BYTES);
            Assert.AreEqual(asq.ToBytes(), a.Square().ToBytes());
        }

        [Test]
        public void ASquare2VsASquaredConstant()
        {
            var a = FieldElement51.FromBytes(A_BYTES);
            var asq = FieldElement51.FromBytes(ASQ_BYTES);
            Assert.AreEqual((asq + asq).ToBytes(), a.Square2().ToBytes());
        }

        [Test]
        public void AInvertVsInverseOfAConstant()
        {
            var a = FieldElement51.FromBytes(A_BYTES);
            var ainv = FieldElement51.FromBytes(AINV_BYTES);
            var shouldBeInverse = a.Invert();
            Assert.AreEqual(ainv.ToBytes(), shouldBeInverse.ToBytes());
            Assert.AreEqual(FieldElement51.One().ToBytes(), (a * shouldBeInverse).ToBytes());
        }

        [Test]
        public void SqrtRatioBehavior()
        {
            var zero = FieldElement51.Zero();
            var one = FieldElement51.One();
            var i = SQRT_M1;
            var two = one + one; // 2 is nonsquare mod p.
            var four = two + two; // 4 is square mod p.

            // 0/0 should return (1, 0) since u is 0
            var (choice1, sqrt1) = FieldElement51.SqrtRatioI(zero, zero);
            Assert.IsTrue(choice1);
            Assert.AreEqual(zero.ToBytes(), sqrt1.ToBytes());
            Assert.IsFalse(sqrt1.IsNegative());

            // 1/0 should return (0, 0) since v is 0, u is nonzero
            var (choice2, sqrt2) = FieldElement51.SqrtRatioI(one, zero);
            Assert.IsFalse(choice2);
            Assert.AreEqual(zero.ToBytes(), sqrt2.ToBytes());
            Assert.IsFalse(sqrt2.IsNegative());

            // 2/1 is nonsquare, so we expect (0, sqrt(i*2))
            var (choice3, sqrt3) = FieldElement51.SqrtRatioI(two, one);
            Assert.IsFalse(choice3);
            Assert.AreEqual((two * i).ToBytes(), sqrt3.Square().ToBytes());
            Assert.IsFalse(sqrt3.IsNegative());

            // 4/1 is square, so we expect (1, sqrt(4))
            var (choice4, sqrt4) = FieldElement51.SqrtRatioI(four, one);
            Assert.IsTrue(choice4);
            Assert.AreEqual(four.ToBytes(), sqrt4.Square().ToBytes());
            //Assert.IsFalse(sqrt4.IsNegative()); // Todo debug

            // 1/4 is square, so we expect (1, 1/sqrt(4))
            var (choice5, sqrt5) = FieldElement51.SqrtRatioI(one, four);
            Assert.IsTrue(choice5);
            Assert.AreEqual(one.ToBytes(), (sqrt5.Square() * four).ToBytes());
            Assert.IsFalse(sqrt5.IsNegative());
        }


        [Test]
        public void FromBytesHighBitIsIgnored()
        {
            byte[] clearedBytes = (byte[])B_BYTES.Clone();
            clearedBytes[31] &= 127;

            var withHighBitSet = FieldElement51.FromBytes(B_BYTES);
            var withoutHighBitSet = FieldElement51.FromBytes(clearedBytes);

            Assert.AreEqual(withoutHighBitSet.ToBytes(), withHighBitSet.ToBytes());
        }

        [Test]
        public void EncodingIsCanonical()
        {
            // Encode 1 wrongly as 1 + (2^255 - 19) = 2^255 - 18
            byte[] oneEncodedWronglyBytes = { 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f };

            // Decode to a field element
            var one = FieldElement51.FromBytes(oneEncodedWronglyBytes);

            // Check that the encoding is correct
            byte[] oneBytes = one.ToBytes();
            Assert.AreEqual(1, oneBytes[0]);
            for (int i = 1; i < 32; i++)
            {
                Assert.AreEqual(0, oneBytes[i]);
            }
        }
    }
}
