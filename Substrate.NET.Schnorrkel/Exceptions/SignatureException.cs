using System;
using System.Collections.Generic;
using System.Text;

namespace Substrate.NET.Schnorrkel.Exceptions
{
    /// <summary>
    /// Exception throws when a signature fail
    /// </summary>
    public class SignatureException : Exception
    {
        /// <summary>
        /// A signature exception with detail message
        /// </summary>
        /// <param name="message"></param>
        public SignatureException(string message) : base(message) { }
    }
}
