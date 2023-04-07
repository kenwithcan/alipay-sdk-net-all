using System;
using System.Xml.Serialization;

namespace Aop.Api.Domain
{
    /// <summary>
    /// OrderItemInfoVO Data Structure.
    /// </summary>
    [Serializable]
    public class OrderItemInfoVO : AopObject
    {
        /// <summary>
        /// 商品个数
        /// </summary>
        [XmlElement("item_cnt")]
        public long ItemCnt { get; set; }

        /// <summary>
        /// 商品itemId
        /// </summary>
        [XmlElement("item_id")]
        public string ItemId { get; set; }

        /// <summary>
        /// 外部商品id
        /// </summary>
        [XmlElement("out_item_id")]
        public string OutItemId { get; set; }

        /// <summary>
        /// 外部商品skuid
        /// </summary>
        [XmlElement("out_sku_id")]
        public string OutSkuId { get; set; }

        /// <summary>
        /// 生成订单时商品的售卖价（单位：分），可以跟上传商品接口的价格不一致
        /// </summary>
        [XmlElement("sale_price")]
        public string SalePrice { get; set; }

        /// <summary>
        /// 商品skuid
        /// </summary>
        [XmlElement("sku_id")]
        public string SkuId { get; set; }
    }
}
