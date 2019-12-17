using System;
using Xunit;
using FluentAssertions;
using Bizanc.io.Matching.Core.Domain;
using Bizanc.io.Matching.Core.Crypto;
using Bizanc.io.Matching.Infra.Connector;
using SimpleBase;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using System.Collections;
using System.Linq;

namespace Bizanc.io.Matching.Test
{
    public class CryptoHelperTest
    {
        [Fact]
        public void Should_Crete_Valid_Address()
        {
            var (pvt, pub) = CryptoHelper.CreateKeyPair();

            pvt.Should().NotBeNull();
            pub.Should().NotBeNull();

            CryptoHelper.IsValidBizancAddress(pub).Should().BeTrue();
        }

        [Fact]
        public void Should_Create_Valid_Signature()
        {
            var (pvt, pub) = CryptoHelper.CreateKeyPair();

            var message = "Message To Sign";

            var signature = CryptoHelper.Sign(message, pvt);

            signature.Should().NotBeNull();

            CryptoHelper.IsValidSignature(message, pub, signature).Should().BeTrue();
        }

        [Fact]
        public void Should_Result_False_For_Invalid_Signature()
        {
            var (pvt, pub) = CryptoHelper.CreateKeyPair();

            var messageToSign = "Message To Sign";

            var messageToVerify = "Message To Verify";

            var signature = CryptoHelper.Sign(messageToSign, pvt);

            signature.Should().NotBeNull();

            CryptoHelper.IsValidSignature(messageToVerify, pub, signature).Should().BeFalse();
        }

        [Fact]
        public void Should_Result_False_For_Invalid_Address()
        {
            var (pvt, pub) = CryptoHelper.CreateKeyPair();

            var messageToSign = "Message To Sign";

            var messageToVerify = "Message To Verify";

            var signature = CryptoHelper.Sign(messageToSign, pvt);

            signature.Should().NotBeNull();

            CryptoHelper.IsValidSignature(messageToVerify, "2ttjRxmEMcfr5dgNXKw8GiHJ1xX5jVgbwUuXUtUZkXiA9aFPAJ", signature).Should().BeFalse();
        }

        [Fact]
        public void Should_Decode_Base58_And_Match_Length()
        {
            var (pvt, pub) = CryptoHelper.CreateKeyPair();

            var decPvt = Base58.Bitcoin.Decode(pvt);
            (decPvt == null).Should().BeFalse();
            decPvt.Length.Should().Be(32);

            var decPub = Base58.Bitcoin.Decode(pub);
            (decPub == null).Should().BeFalse();
            decPub.Length.Should().Be(36);
        }

        [Fact]
        public void Should_Create_Valid_Hash_From_String()
        {
            var strToHash = "String to Hash";
            var computedHash = CryptoHelper.Hash(strToHash);

            byte[] hashToCompare;
            using (var algorithm = SHA256.Create())
            {
                hashToCompare = algorithm.ComputeHash(Encoding.UTF8.GetBytes(strToHash));
            }

            computedHash.SequenceEqual(hashToCompare).Should().BeTrue();
        }

        [Fact]
        public void Should_Create_Valid_Hash_From_Bytes()
        {
            var strToHash = "String to Hash";
            var computedHash = CryptoHelper.Hash(Encoding.UTF8.GetBytes(strToHash));

            byte[] hashToCompare;
            using (var algorithm = SHA256.Create())
            {
                hashToCompare = algorithm.ComputeHash(Encoding.UTF8.GetBytes(strToHash));
            }

            computedHash.SequenceEqual(hashToCompare).Should().BeTrue();
        }

        [Fact]
        public void Should_Return_Valid_Four_Bytes_CheckSum()
        {
            var stringToCheckSum = "String to Checksum";

            var computedCheckSum = CryptoHelper.CalculateCheckSum(new Span<byte>(Encoding.UTF8.GetBytes(stringToCheckSum)), 4);

            Span<byte> checkSumToCompare;
            using (var algorithm = SHA256.Create())
            {
                var hashToCompare = algorithm.ComputeHash(Encoding.UTF8.GetBytes(stringToCheckSum));
                hashToCompare = algorithm.ComputeHash(hashToCompare);

                checkSumToCompare = new Span<byte>(hashToCompare).Slice(0, 4);
            }

            computedCheckSum.SequenceEqual(checkSumToCompare).Should().BeTrue();
        }

        [Fact]
        public void Should_Return_True_For_Valid_Address_String_With_CheckSum()
        {
            var address = "2ttjRxmEMcfr5egNXKw8GiHJ1xX5jVgbwUuXUtUZkXiA9aFPAJ";

            CryptoHelper.IsValidCheckSum(address, 4).Should().BeTrue();
        }

        [Fact]
        public void Should_Return_False_For_Invalid_Address_String_With_CheckSum()
        {
            var address = "2ttjRxmEMcfr5dgNXKw8GiHJ1xX5jVgbwUuXUtUZkXiA9aFPAJ";

            CryptoHelper.IsValidCheckSum(address, 4).Should().BeFalse();
        }

        public void Should_Return_True_For_Valid_Address_Bytes_With_CheckSum()
        {
            var address = Base58.Bitcoin.Decode("2ttjRxmEMcfr5egNXKw8GiHJ1xX5jVgbwUuXUtUZkXiA9aFPAJ");

            CryptoHelper.IsValidCheckSum(address, 4).Should().BeTrue();
        }

        [Fact]
        public void Should_Return_False_For_Invalid_Address_Bytes_With_CheckSum()
        {
            var address = Base58.Bitcoin.Decode("2ttjRxmEMcfr5dgNXKw8GiHJ1xX5jVgbwUuXUtUZkXiA9aFPAJ");

            CryptoHelper.IsValidCheckSum(address, 4).Should().BeFalse();
        }
    }
}