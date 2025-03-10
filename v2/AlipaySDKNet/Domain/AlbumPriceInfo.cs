using System;
using System.Xml.Serialization;

namespace Aop.Api.Domain
{
    /// <summary>
    /// AlbumPriceInfo Data Structure.
    /// </summary>
    [Serializable]
    public class AlbumPriceInfo : AopObject
    {
        /// <summary>
        /// 专辑价格，单位元。已废弃。 当前字段已废弃(废弃actual_price字段，使用price字段)
        /// </summary>
        [XmlElement("actual_price")]
        public string ActualPrice { get; set; }

        /// <summary>
        /// 仅面向专辑购买时无法通过专辑ID发起的场景，无相关需求可不填。
        /// </summary>
        [XmlElement("item_id")]
        public string ItemId { get; set; }

        /// <summary>
        /// 专辑原价。单位元，最多两位小数。收费专辑必填。
        /// </summary>
        [XmlElement("price")]
        public string Price { get; set; }

        /// <summary>
        /// 专辑的销售方式
        /// </summary>
        [XmlElement("sell_type")]
        public string SellType { get; set; }
    }
}
