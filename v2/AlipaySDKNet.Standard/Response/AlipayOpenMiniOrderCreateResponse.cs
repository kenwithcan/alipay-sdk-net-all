using System;
using System.Xml.Serialization;

namespace Aop.Api.Response
{
    /// <summary>
    /// AlipayOpenMiniOrderCreateResponse.
    /// </summary>
    public class AlipayOpenMiniOrderCreateResponse : AopResponse
    {
        /// <summary>
        /// 交易组件订单号。可以把获取到的order_id作为<a href="https://opendocs.alipay.com/mini/05x9kv?scene=de4d6a1e0c6e423b9eefa7c3a6dcb7a5&pathHash=779dc517">alipay.trade.create（统一收单交易创建接口）</a>extend_params.trade_component_order_id的入参进行关联。
        /// </summary>
        [XmlElement("order_id")]
        public string OrderId { get; set; }

        /// <summary>
        /// 外部商户订单号
        /// </summary>
        [XmlElement("out_order_id")]
        public string OutOrderId { get; set; }
    }
}
