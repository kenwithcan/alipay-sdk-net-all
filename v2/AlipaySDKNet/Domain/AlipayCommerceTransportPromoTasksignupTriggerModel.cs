using System;
using System.Xml.Serialization;

namespace Aop.Api.Domain
{
    /// <summary>
    /// AlipayCommerceTransportPromoTasksignupTriggerModel Data Structure.
    /// </summary>
    [Serializable]
    public class AlipayCommerceTransportPromoTasksignupTriggerModel : AopObject
    {
        /// <summary>
        /// 用于标记支付宝用户在应用下的唯一标识
        /// </summary>
        [XmlElement("open_id")]
        public string OpenId { get; set; }

        /// <summary>
        /// 任务场景
        /// </summary>
        [XmlElement("task_scene")]
        public string TaskScene { get; set; }

        /// <summary>
        /// 定义查询任务来源
        /// </summary>
        [XmlElement("task_source")]
        public string TaskSource { get; set; }

        /// <summary>
        /// 支付宝用户的userId。
        /// </summary>
        [XmlElement("user_id")]
        public string UserId { get; set; }
    }
}
