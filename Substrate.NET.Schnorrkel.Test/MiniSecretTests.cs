using NUnit.Framework;
using Substrate.NET.Schnorrkel.Keys;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Substrate.NET.Schnorrkel.Test
{
    internal class MiniSecretTests
    {
        [Test]
        public void PublicKeyFromMiniSecretAndexpandedSecret_ShouldSucceed()
        {
            byte[] seed = new byte[32];
            using RandomNumberGenerator randomGenerator = RandomNumberGenerator.Create();
            randomGenerator.GetBytes(seed);

            var miniSecretExpandEd = new MiniSecret(seed, ExpandMode.Ed25519);

            Assert.That(
                miniSecretExpandEd.ExpandToPublic().Key, 
                Is.EqualTo(miniSecretExpandEd.ExpandToSecret().ExpandToPublic().Key));

            var miniSecretExpandUniform = new MiniSecret(seed, ExpandMode.Uniform);

            Assert.That(
                miniSecretExpandUniform.ExpandToPublic().Key, 
                Is.EqualTo(miniSecretExpandUniform.ExpandToSecret().ExpandToPublic().Key));
        }
    }
}
