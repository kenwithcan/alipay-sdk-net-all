using System;
using System.Xml.Serialization;

namespace Aop.Api.Response
{
    /// <summary>
    /// AlipayPcreditHuabeiMerchantActivityQueryResponse.
    /// </summary>
    public class AlipayPcreditHuabeiMerchantActivityQueryResponse : AopResponse
    {
        /// <summary>
        /// 出资户账号
        /// </summary>
        [XmlElement("account_id")]
        public string AccountId { get; set; }

        /// <summary>
        /// 活动模版ID
        /// </summary>
        [XmlElement("aggr_id")]
        public string AggrId { get; set; }

        /// <summary>
        /// 活动出资类型
        /// </summary>
        [XmlElement("fund_type")]
        public string FundType { get; set; }

        /// <summary>
        /// DRAFT:草稿;START_SUCCEED:发布;PAUSE_SUCCEED:暂停;USELESS:终止
        /// </summary>
        [XmlElement("status")]
        public string Status { get; set; }

        /// <summary>
        /// ALL代表全场贴息 ORDER代表订单贴息
        /// </summary>
        [XmlElement("subsidy_scope")]
        public string SubsidyScope { get; set; }
    }
}
