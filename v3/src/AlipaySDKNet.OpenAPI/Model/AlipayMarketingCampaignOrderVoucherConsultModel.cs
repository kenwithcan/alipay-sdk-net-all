/*
 * 支付宝开放平台API
 *
 * 支付宝开放平台v3协议文档
 *
 * The version of the OpenAPI document: 2025-02-19
 * Generated by: https://github.com/openapitools/openapi-generator.git
 */


using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.IO;
using System.Runtime.Serialization;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;
using Newtonsoft.Json.Linq;
using System.ComponentModel.DataAnnotations;
using OpenAPIDateConverter = AlipaySDKNet.OpenAPI.Client.OpenAPIDateConverter;

namespace AlipaySDKNet.OpenAPI.Model
{
    /// <summary>
    /// AlipayMarketingCampaignOrderVoucherConsultModel
    /// </summary>
    [DataContract(Name = "AlipayMarketingCampaignOrderVoucherConsultModel")]
    public partial class AlipayMarketingCampaignOrderVoucherConsultModel : IEquatable<AlipayMarketingCampaignOrderVoucherConsultModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMarketingCampaignOrderVoucherConsultModel" /> class.
        /// </summary>
        /// <param name="businessParam">业务参数大字段，优惠咨询的控制参数，json格式；目前支持传入useBigAmountSkipOrderThold为N来控制不使用大金额跳过优惠的订单门槛检查；默认不传；.</param>
        /// <param name="itemConsultList">商品咨询请求列表（当需要咨询单品券时必传，如果某商品不希望参与本次单品优惠咨询则不传递对应信息即可）.</param>
        /// <param name="orderAmount">订单金额（如同时享受商户自有优惠请先扣除后传入），单位为元，最多2位小数.</param>
        /// <param name="sceneCode">场景码：默认(DEFAULT).</param>
        /// <param name="specifiedAppId">券指定的核销appid（如果配券时指定了核销范围为线上小程序及相应的appid则此处必传）.</param>
        public AlipayMarketingCampaignOrderVoucherConsultModel(string businessParam = default(string), List<ItemConsultRequest> itemConsultList = default(List<ItemConsultRequest>), string orderAmount = default(string), List<string> sceneCode = default(List<string>), string specifiedAppId = default(string))
        {
            this.BusinessParam = businessParam;
            this.ItemConsultList = itemConsultList;
            this.OrderAmount = orderAmount;
            this.SceneCode = sceneCode;
            this.SpecifiedAppId = specifiedAppId;
        }

        /// <summary>
        /// 业务参数大字段，优惠咨询的控制参数，json格式；目前支持传入useBigAmountSkipOrderThold为N来控制不使用大金额跳过优惠的订单门槛检查；默认不传；
        /// </summary>
        /// <value>业务参数大字段，优惠咨询的控制参数，json格式；目前支持传入useBigAmountSkipOrderThold为N来控制不使用大金额跳过优惠的订单门槛检查；默认不传；</value>
        [DataMember(Name = "business_param", EmitDefaultValue = false)]
        public string BusinessParam { get; set; }

        /// <summary>
        /// 商品咨询请求列表（当需要咨询单品券时必传，如果某商品不希望参与本次单品优惠咨询则不传递对应信息即可）
        /// </summary>
        /// <value>商品咨询请求列表（当需要咨询单品券时必传，如果某商品不希望参与本次单品优惠咨询则不传递对应信息即可）</value>
        [DataMember(Name = "item_consult_list", EmitDefaultValue = false)]
        public List<ItemConsultRequest> ItemConsultList { get; set; }

        /// <summary>
        /// 订单金额（如同时享受商户自有优惠请先扣除后传入），单位为元，最多2位小数
        /// </summary>
        /// <value>订单金额（如同时享受商户自有优惠请先扣除后传入），单位为元，最多2位小数</value>
        [DataMember(Name = "order_amount", EmitDefaultValue = false)]
        public string OrderAmount { get; set; }

        /// <summary>
        /// 场景码：默认(DEFAULT)
        /// </summary>
        /// <value>场景码：默认(DEFAULT)</value>
        [DataMember(Name = "scene_code", EmitDefaultValue = false)]
        public List<string> SceneCode { get; set; }

        /// <summary>
        /// 券指定的核销appid（如果配券时指定了核销范围为线上小程序及相应的appid则此处必传）
        /// </summary>
        /// <value>券指定的核销appid（如果配券时指定了核销范围为线上小程序及相应的appid则此处必传）</value>
        [DataMember(Name = "specified_app_id", EmitDefaultValue = false)]
        public string SpecifiedAppId { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayMarketingCampaignOrderVoucherConsultModel {\n");
            sb.Append("  BusinessParam: ").Append(BusinessParam).Append("\n");
            sb.Append("  ItemConsultList: ").Append(ItemConsultList).Append("\n");
            sb.Append("  OrderAmount: ").Append(OrderAmount).Append("\n");
            sb.Append("  SceneCode: ").Append(SceneCode).Append("\n");
            sb.Append("  SpecifiedAppId: ").Append(SpecifiedAppId).Append("\n");
            sb.Append("}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Returns the JSON string presentation of the object
        /// </summary>
        /// <returns>JSON string presentation of the object</returns>
        public virtual string ToJson()
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(this, Newtonsoft.Json.Formatting.Indented);
        }

        /// <summary>
        /// Returns true if objects are equal
        /// </summary>
        /// <param name="input">Object to be compared</param>
        /// <returns>Boolean</returns>
        public override bool Equals(object input)
        {
            return this.Equals(input as AlipayMarketingCampaignOrderVoucherConsultModel);
        }

        /// <summary>
        /// Returns true if AlipayMarketingCampaignOrderVoucherConsultModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayMarketingCampaignOrderVoucherConsultModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayMarketingCampaignOrderVoucherConsultModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.BusinessParam == input.BusinessParam ||
                    (this.BusinessParam != null &&
                    this.BusinessParam.Equals(input.BusinessParam))
                ) && 
                (
                    this.ItemConsultList == input.ItemConsultList ||
                    this.ItemConsultList != null &&
                    input.ItemConsultList != null &&
                    this.ItemConsultList.SequenceEqual(input.ItemConsultList)
                ) && 
                (
                    this.OrderAmount == input.OrderAmount ||
                    (this.OrderAmount != null &&
                    this.OrderAmount.Equals(input.OrderAmount))
                ) && 
                (
                    this.SceneCode == input.SceneCode ||
                    this.SceneCode != null &&
                    input.SceneCode != null &&
                    this.SceneCode.SequenceEqual(input.SceneCode)
                ) && 
                (
                    this.SpecifiedAppId == input.SpecifiedAppId ||
                    (this.SpecifiedAppId != null &&
                    this.SpecifiedAppId.Equals(input.SpecifiedAppId))
                );
        }

        /// <summary>
        /// Gets the hash code
        /// </summary>
        /// <returns>Hash code</returns>
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                int hashCode = 41;
                if (this.BusinessParam != null)
                {
                    hashCode = (hashCode * 59) + this.BusinessParam.GetHashCode();
                }
                if (this.ItemConsultList != null)
                {
                    hashCode = (hashCode * 59) + this.ItemConsultList.GetHashCode();
                }
                if (this.OrderAmount != null)
                {
                    hashCode = (hashCode * 59) + this.OrderAmount.GetHashCode();
                }
                if (this.SceneCode != null)
                {
                    hashCode = (hashCode * 59) + this.SceneCode.GetHashCode();
                }
                if (this.SpecifiedAppId != null)
                {
                    hashCode = (hashCode * 59) + this.SpecifiedAppId.GetHashCode();
                }
                return hashCode;
            }
        }

        /// <summary>
        /// To validate all properties of the instance
        /// </summary>
        /// <param name="validationContext">Validation context</param>
        /// <returns>Validation Result</returns>
        public IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> Validate(ValidationContext validationContext)
        {
            yield break;
        }
    }

}
