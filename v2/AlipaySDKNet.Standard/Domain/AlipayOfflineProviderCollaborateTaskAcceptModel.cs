using System;
using System.Xml.Serialization;

namespace Aop.Api.Domain
{
    /// <summary>
    /// AlipayOfflineProviderCollaborateTaskAcceptModel Data Structure.
    /// </summary>
    [Serializable]
    public class AlipayOfflineProviderCollaborateTaskAcceptModel : AopObject
    {
        /// <summary>
        /// 当前操作在业务系统实际发生的时间。
        /// </summary>
        [XmlElement("biz_time")]
        public string BizTime { get; set; }

        /// <summary>
        /// 外部系统对应操作流水号
        /// </summary>
        [XmlElement("out_biz_no")]
        public string OutBizNo { get; set; }

        /// <summary>
        /// 拉取任务时获得的任务号。
        /// </summary>
        [XmlElement("task_no")]
        public string TaskNo { get; set; }
    }
}
