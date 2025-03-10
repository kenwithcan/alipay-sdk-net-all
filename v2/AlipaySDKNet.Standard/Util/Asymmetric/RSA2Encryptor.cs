using System;
using System.Text;
using Org.BouncyCastle.Security;

namespace Aop.Api.Util.Asymmetric
{
    /// <summary>
    /// RSA2算法加密器
    /// 签名部分采用SHA256算法进行摘要计算，其余部分与RSA算法相同
    /// </summary>
    public class RSA2Encryptor : RSAEncryptor
    {
        /// <summary>
        /// RSA2算法签名采用SHA256摘要算法
        /// </summary>
        /// <returns>摘要算法名称</returns>
        protected override string GetShaType()
        {
            return "SHA256";
        }

        protected override string DoSign(string content, string charset, string privateKey)
        {
            var priKey = PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
            byte[] data = Encoding.GetEncoding(charset).GetBytes(content);
            var normalSig = SignerUtilities.GetSigner("SHA256withRSA");
            normalSig.Init(true, priKey);
            normalSig.BlockUpdate(data, 0, data.Length);
            byte[] sign = normalSig.GenerateSignature();
            return Convert.ToBase64String(sign);
        }
    }
}
