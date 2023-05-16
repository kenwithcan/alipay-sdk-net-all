using System;
using System.Xml.Serialization;

namespace Aop.Api.Domain
{
    /// <summary>
    /// AlipayCommerceEcBalanceDownloadurlQueryModel Data Structure.
    /// </summary>
    [Serializable]
    public class AlipayCommerceEcBalanceDownloadurlQueryModel : AopObject
    {
        /// <summary>
        /// 共同账户ID
        /// </summary>
        [XmlElement("account_id")]
        public string AccountId { get; set; }

        /// <summary>
        /// 授权签约协议号
        /// </summary>
        [XmlElement("agreement_no")]
        public string AgreementNo { get; set; }

        /// <summary>
        /// 账单时间
        /// </summary>
        [XmlElement("bill_date")]
        public string BillDate { get; set; }

        /// <summary>
        /// 账单类型
        /// </summary>
        [XmlElement("bill_type")]
        public string BillType { get; set; }

        /// <summary>
        /// 企业ID
        /// </summary>
        [XmlElement("enterprise_id")]
        public string EnterpriseId { get; set; }
    }
}
