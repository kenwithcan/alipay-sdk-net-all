using System;
using System.Xml.Serialization;

namespace Aop.Api.Domain
{
    /// <summary>
    /// AppItemVoucherQueryUseTimeInfo Data Structure.
    /// </summary>
    [Serializable]
    public class AppItemVoucherQueryUseTimeInfo : AopObject
    {
        /// <summary>
        /// 绝对核销时间
        /// </summary>
        [XmlElement("app_item_absolute_period_info")]
        public AppItemAbsoluteQueryPeriodInfo AppItemAbsolutePeriodInfo { get; set; }

        /// <summary>
        /// 相对核销时间
        /// </summary>
        [XmlElement("app_item_relative_period_info")]
        public AppItemRelativeQueryPeriodInfo AppItemRelativePeriodInfo { get; set; }

        /// <summary>
        /// 券有效期 【枚举值】 绝对时间 : ABSOLUTE 相对时间: RELATIVE
        /// </summary>
        [XmlElement("period_type")]
        public string PeriodType { get; set; }
    }
}
