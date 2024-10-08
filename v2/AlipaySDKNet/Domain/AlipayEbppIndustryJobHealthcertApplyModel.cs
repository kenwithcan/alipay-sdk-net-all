using System;
using System.Xml.Serialization;

namespace Aop.Api.Domain
{
    /// <summary>
    /// AlipayEbppIndustryJobHealthcertApplyModel Data Structure.
    /// </summary>
    [Serializable]
    public class AlipayEbppIndustryJobHealthcertApplyModel : AopObject
    {
        /// <summary>
        /// 使用支付宝就业健康证认证服务后，回跳到该商户指定的地址
        /// </summary>
        [XmlElement("certify_return_url")]
        public string CertifyReturnUrl { get; set; }

        /// <summary>
        /// 6位行政区域编码 至少到城市级编码，否则岗位无法展示，建议传到区(县)级编码，如: 浙江省杭州市西湖区=330106。 <a href="https://jiuye.yuque.com/org-wiki-jiuye-cpfcqs/araxo9/yi0uix3f0babcfzi">全量城市行政区划编码（2020Q1版本）</a> <a href="https://jiuye.yuque.com/org-wiki-jiuye-cpfcqs/araxo9/ed5yn3asbtes7ni4">全量区县行政区划编码（2020Q1版本）</a>
        /// </summary>
        [XmlElement("city_code")]
        public string CityCode { get; set; }
    }
}
