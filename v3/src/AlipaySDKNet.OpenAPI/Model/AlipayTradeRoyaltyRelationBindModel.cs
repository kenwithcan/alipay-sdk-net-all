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
    /// AlipayTradeRoyaltyRelationBindModel
    /// </summary>
    [DataContract(Name = "AlipayTradeRoyaltyRelationBindModel")]
    public partial class AlipayTradeRoyaltyRelationBindModel : IEquatable<AlipayTradeRoyaltyRelationBindModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayTradeRoyaltyRelationBindModel" /> class.
        /// </summary>
        /// <param name="outRequestNo">外部请求号，由商家自定义。32个字符以内，仅可包含字母、数字、下划线。需保证在商户端不重复。.</param>
        /// <param name="receiverList">分账接收方列表，单次传入最多20个.</param>
        public AlipayTradeRoyaltyRelationBindModel(string outRequestNo = default(string), List<RoyaltyEntity> receiverList = default(List<RoyaltyEntity>))
        {
            this.OutRequestNo = outRequestNo;
            this.ReceiverList = receiverList;
        }

        /// <summary>
        /// 外部请求号，由商家自定义。32个字符以内，仅可包含字母、数字、下划线。需保证在商户端不重复。
        /// </summary>
        /// <value>外部请求号，由商家自定义。32个字符以内，仅可包含字母、数字、下划线。需保证在商户端不重复。</value>
        [DataMember(Name = "out_request_no", EmitDefaultValue = false)]
        public string OutRequestNo { get; set; }

        /// <summary>
        /// 分账接收方列表，单次传入最多20个
        /// </summary>
        /// <value>分账接收方列表，单次传入最多20个</value>
        [DataMember(Name = "receiver_list", EmitDefaultValue = false)]
        public List<RoyaltyEntity> ReceiverList { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayTradeRoyaltyRelationBindModel {\n");
            sb.Append("  OutRequestNo: ").Append(OutRequestNo).Append("\n");
            sb.Append("  ReceiverList: ").Append(ReceiverList).Append("\n");
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
            return this.Equals(input as AlipayTradeRoyaltyRelationBindModel);
        }

        /// <summary>
        /// Returns true if AlipayTradeRoyaltyRelationBindModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayTradeRoyaltyRelationBindModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayTradeRoyaltyRelationBindModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.OutRequestNo == input.OutRequestNo ||
                    (this.OutRequestNo != null &&
                    this.OutRequestNo.Equals(input.OutRequestNo))
                ) && 
                (
                    this.ReceiverList == input.ReceiverList ||
                    this.ReceiverList != null &&
                    input.ReceiverList != null &&
                    this.ReceiverList.SequenceEqual(input.ReceiverList)
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
                if (this.OutRequestNo != null)
                {
                    hashCode = (hashCode * 59) + this.OutRequestNo.GetHashCode();
                }
                if (this.ReceiverList != null)
                {
                    hashCode = (hashCode * 59) + this.ReceiverList.GetHashCode();
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
