using System;
using System.Xml.Serialization;

namespace Aop.Api.Domain
{
    /// <summary>
    /// AlipayCommerceTransportVehownerbaseBenefitinterestQueryModel Data Structure.
    /// </summary>
    [Serializable]
    public class AlipayCommerceTransportVehownerbaseBenefitinterestQueryModel : AopObject
    {
        /// <summary>
        /// 权益编码，用于获取对应的权益信息，从会员信息获取。
        /// </summary>
        [XmlElement("benefit_id")]
        public string BenefitId { get; set; }

        /// <summary>
        /// 用于标记支付宝用户在应用下的唯一标识
        /// </summary>
        [XmlElement("open_id")]
        public string OpenId { get; set; }

        /// <summary>
        /// 支付宝用户的userId。
        /// </summary>
        [XmlElement("user_id")]
        public string UserId { get; set; }
    }
}
