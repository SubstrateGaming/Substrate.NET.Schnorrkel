using System;
using System.Collections.Generic;
using System.Text;

namespace Substrate.NET.Schnorrkel.Exceptions
{
    /// <summary>
    /// Exceptions throws by Transcript class
    /// </summary>
    public class TranscriptException : Exception
    {
        /// <summary>
        /// A Transcript exception with detail message
        /// </summary>
        /// <param name="message"></param>
        public TranscriptException(string message) : base(message) { }
    }
}
