using System;
using System.Xml.Serialization;

namespace Aop.Api.Domain
{
    /// <summary>
    /// DeviceExtAttribute Data Structure.
    /// </summary>
    [Serializable]
    public class DeviceExtAttribute : AopObject
    {
        /// <summary>
        /// 商家编号，由服务商定义，需要保证在服务商下唯一
        /// </summary>
        [XmlElement("external_id")]
        public string ExternalId { get; set; }

        /// <summary>
        /// 外部门店 ID，如果是可用绑定必有
        /// </summary>
        [XmlElement("external_shop_id")]
        public string ExternalShopId { get; set; }

        /// <summary>
        /// 可用绑定时必有，用于设备左上角展示，可以区分设备所在门店
        /// </summary>
        [XmlElement("shop_name")]
        public string ShopName { get; set; }

        /// <summary>
        /// 可用绑定时选填，用于设备左上角展示，可以区分设备所在门店
        /// </summary>
        [XmlElement("shop_nick_name")]
        public string ShopNickName { get; set; }

        /// <summary>
        /// 卖进方案id，作业时有卖进方案的必传
        /// </summary>
        [XmlElement("solution_id")]
        public string SolutionId { get; set; }

        /// <summary>
        /// 进件服务商 PID
        /// </summary>
        [XmlElement("source")]
        public string Source { get; set; }

        /// <summary>
        /// 表示服务商在开放平台注册的 SPI 服务应用的 app_id，用于标识服务商身份
        /// </summary>
        [XmlElement("spi_app_id")]
        public string SpiAppId { get; set; }

        /// <summary>
        /// 服务商内部唯一标识商家、商家门店等字段信息；
        /// </summary>
        [XmlElement("terminal_bind_info")]
        public string TerminalBindInfo { get; set; }
    }
}
