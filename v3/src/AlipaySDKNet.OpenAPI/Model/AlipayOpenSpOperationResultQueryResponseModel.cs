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
    /// AlipayOpenSpOperationResultQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayOpenSpOperationResultQueryResponseModel")]
    public partial class AlipayOpenSpOperationResultQueryResponseModel : IEquatable<AlipayOpenSpOperationResultQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenSpOperationResultQueryResponseModel" /> class.
        /// </summary>
        /// <param name="bindUserId">商户支付宝pid。仅间连场景，且存在绑定关系时返回值。.</param>
        /// <param name="handleStatus">代运营操作结果。 SUCCESS：代表成功。 PROCESS：待商家确认中。 NO_PERMISSION：表示当前商家支付宝账号无权限操作。需要提醒商家切换成发起授权时指定的支付宝账号。 NONE：表示不存在代运营绑定或授权关系。 NONE_ACCOUNT：间连商家推荐支付宝账号列表为空。.</param>
        /// <param name="merchantNo">支付宝商户号。间连场景为商户smid，直连场景为商户支付宝pid.</param>
        public AlipayOpenSpOperationResultQueryResponseModel(string bindUserId = default(string), string handleStatus = default(string), string merchantNo = default(string))
        {
            this.BindUserId = bindUserId;
            this.HandleStatus = handleStatus;
            this.MerchantNo = merchantNo;
        }

        /// <summary>
        /// 商户支付宝pid。仅间连场景，且存在绑定关系时返回值。
        /// </summary>
        /// <value>商户支付宝pid。仅间连场景，且存在绑定关系时返回值。</value>
        [DataMember(Name = "bind_user_id", EmitDefaultValue = false)]
        public string BindUserId { get; set; }

        /// <summary>
        /// 代运营操作结果。 SUCCESS：代表成功。 PROCESS：待商家确认中。 NO_PERMISSION：表示当前商家支付宝账号无权限操作。需要提醒商家切换成发起授权时指定的支付宝账号。 NONE：表示不存在代运营绑定或授权关系。 NONE_ACCOUNT：间连商家推荐支付宝账号列表为空。
        /// </summary>
        /// <value>代运营操作结果。 SUCCESS：代表成功。 PROCESS：待商家确认中。 NO_PERMISSION：表示当前商家支付宝账号无权限操作。需要提醒商家切换成发起授权时指定的支付宝账号。 NONE：表示不存在代运营绑定或授权关系。 NONE_ACCOUNT：间连商家推荐支付宝账号列表为空。</value>
        [DataMember(Name = "handle_status", EmitDefaultValue = false)]
        public string HandleStatus { get; set; }

        /// <summary>
        /// 支付宝商户号。间连场景为商户smid，直连场景为商户支付宝pid
        /// </summary>
        /// <value>支付宝商户号。间连场景为商户smid，直连场景为商户支付宝pid</value>
        [DataMember(Name = "merchant_no", EmitDefaultValue = false)]
        public string MerchantNo { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenSpOperationResultQueryResponseModel {\n");
            sb.Append("  BindUserId: ").Append(BindUserId).Append("\n");
            sb.Append("  HandleStatus: ").Append(HandleStatus).Append("\n");
            sb.Append("  MerchantNo: ").Append(MerchantNo).Append("\n");
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
            return this.Equals(input as AlipayOpenSpOperationResultQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenSpOperationResultQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenSpOperationResultQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenSpOperationResultQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.BindUserId == input.BindUserId ||
                    (this.BindUserId != null &&
                    this.BindUserId.Equals(input.BindUserId))
                ) && 
                (
                    this.HandleStatus == input.HandleStatus ||
                    (this.HandleStatus != null &&
                    this.HandleStatus.Equals(input.HandleStatus))
                ) && 
                (
                    this.MerchantNo == input.MerchantNo ||
                    (this.MerchantNo != null &&
                    this.MerchantNo.Equals(input.MerchantNo))
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
                if (this.BindUserId != null)
                {
                    hashCode = (hashCode * 59) + this.BindUserId.GetHashCode();
                }
                if (this.HandleStatus != null)
                {
                    hashCode = (hashCode * 59) + this.HandleStatus.GetHashCode();
                }
                if (this.MerchantNo != null)
                {
                    hashCode = (hashCode * 59) + this.MerchantNo.GetHashCode();
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
