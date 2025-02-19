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
    /// AlipayMarketingCardActivateurlApplyResponseModel
    /// </summary>
    [DataContract(Name = "AlipayMarketingCardActivateurlApplyResponseModel")]
    public partial class AlipayMarketingCardActivateurlApplyResponseModel : IEquatable<AlipayMarketingCardActivateurlApplyResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayMarketingCardActivateurlApplyResponseModel" /> class.
        /// </summary>
        /// <param name="applyCardUrl">会员卡领卡链接(使用时需URLDecode解码)。商户获取此链接后可投放到服务窗消息、店铺二维码等。.</param>
        public AlipayMarketingCardActivateurlApplyResponseModel(string applyCardUrl = default(string))
        {
            this.ApplyCardUrl = applyCardUrl;
        }

        /// <summary>
        /// 会员卡领卡链接(使用时需URLDecode解码)。商户获取此链接后可投放到服务窗消息、店铺二维码等。
        /// </summary>
        /// <value>会员卡领卡链接(使用时需URLDecode解码)。商户获取此链接后可投放到服务窗消息、店铺二维码等。</value>
        [DataMember(Name = "apply_card_url", EmitDefaultValue = false)]
        public string ApplyCardUrl { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayMarketingCardActivateurlApplyResponseModel {\n");
            sb.Append("  ApplyCardUrl: ").Append(ApplyCardUrl).Append("\n");
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
            return this.Equals(input as AlipayMarketingCardActivateurlApplyResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayMarketingCardActivateurlApplyResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayMarketingCardActivateurlApplyResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayMarketingCardActivateurlApplyResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.ApplyCardUrl == input.ApplyCardUrl ||
                    (this.ApplyCardUrl != null &&
                    this.ApplyCardUrl.Equals(input.ApplyCardUrl))
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
                if (this.ApplyCardUrl != null)
                {
                    hashCode = (hashCode * 59) + this.ApplyCardUrl.GetHashCode();
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
