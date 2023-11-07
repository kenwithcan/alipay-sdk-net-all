using System;
using System.Xml.Serialization;

namespace Aop.Api.Domain
{
    /// <summary>
    /// AlipayCommerceEcDepartmentUpgradeQueryModel Data Structure.
    /// </summary>
    [Serializable]
    public class AlipayCommerceEcDepartmentUpgradeQueryModel : AopObject
    {
        /// <summary>
        /// 主企业id
        /// </summary>
        [XmlElement("enterprise_id")]
        public string EnterpriseId { get; set; }

        /// <summary>
        /// 升级工单id
        /// </summary>
        [XmlElement("process_id")]
        public string ProcessId { get; set; }
    }
}
