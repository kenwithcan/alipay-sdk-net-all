using System;
using System.Xml.Serialization;

namespace Aop.Api.Domain
{
    /// <summary>
    /// AlipayUserDtbankActivitybillQueryModel Data Structure.
    /// </summary>
    [Serializable]
    public class AlipayUserDtbankActivitybillQueryModel : AopObject
    {
        /// <summary>
        /// 银行活动id/解决方案id
        /// </summary>
        [XmlElement("activity_id")]
        public string ActivityId { get; set; }

        /// <summary>
        /// 申请查询的账单类型 当前字段已废弃(数字分行账单已经全部迁移)
        /// </summary>
        [XmlElement("bill_type")]
        public string BillType { get; set; }
    }
}
