using System;
using System.Xml.Serialization;

namespace Aop.Api.Domain
{
    /// <summary>
    /// AlipayOpenAppRoomrentDirectModifyModel Data Structure.
    /// </summary>
    [Serializable]
    public class AlipayOpenAppRoomrentDirectModifyModel : AopObject
    {
        /// <summary>
        /// 支付宝平台侧商品ID，是支付宝平台侧商品的唯一标识，后续与平台交互，需要使用该 ID，建议持久化。
        /// </summary>
        [XmlElement("item_id")]
        public string ItemId { get; set; }

        /// <summary>
        /// 操作商品上下架。
        /// </summary>
        [XmlElement("opt_type")]
        public string OptType { get; set; }

        /// <summary>
        /// 要求 APPID 下全局唯一
        /// </summary>
        [XmlElement("out_item_id")]
        public string OutItemId { get; set; }

        /// <summary>
        /// 目前支持库存区间1~100000
        /// </summary>
        [XmlElement("stock_num")]
        public long StockNum { get; set; }
    }
}
