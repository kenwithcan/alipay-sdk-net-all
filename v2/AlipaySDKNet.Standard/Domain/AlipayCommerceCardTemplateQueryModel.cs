using System;
using System.Xml.Serialization;

namespace Aop.Api.Domain
{
    /// <summary>
    /// AlipayCommerceCardTemplateQueryModel Data Structure.
    /// </summary>
    [Serializable]
    public class AlipayCommerceCardTemplateQueryModel : AopObject
    {
        /// <summary>
        /// 卡模版ID
        /// </summary>
        [XmlElement("card_template_id")]
        public string CardTemplateId { get; set; }

        /// <summary>
        /// 商户pid
        /// </summary>
        [XmlElement("merchant_pid")]
        public string MerchantPid { get; set; }
    }
}
