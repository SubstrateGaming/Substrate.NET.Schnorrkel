using NUnit.Framework;
using Substrate.NET.Schnorrkel.Keys;
using SubstrateNetApi;
using SubstrateNetApi.Model.Types.Base;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Substrate.NET.Schnorrkel.Test
{
    internal class KeyPairTests
    {
        [Test]
        [TestCase("28b0ae221c6bb06856b287f60d7ea0d98552ea5a16db16956849aa371db3eb51fd190cce74df356432b410bd64682309d6dedb27c76845daf388557cbac3ca3446ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a")]
        public void FromHalfEd25519_ToHalfEd25519_WithValidData_ShouldSucceed(string hex)
        {
            var keypairBytes = Utils.HexToByteArray(hex);
            var keyPair = KeyPair.FromHalfEd25519Bytes(keypairBytes);

            Assert.That(keypairBytes, Is.EquivalentTo(keyPair.ToHalfEd25519Bytes()));
        }
    }
}
