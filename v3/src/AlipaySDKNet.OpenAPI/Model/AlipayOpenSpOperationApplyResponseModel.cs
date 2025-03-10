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
    /// AlipayOpenSpOperationApplyResponseModel
    /// </summary>
    [DataContract(Name = "AlipayOpenSpOperationApplyResponseModel")]
    public partial class AlipayOpenSpOperationApplyResponseModel : IEquatable<AlipayOpenSpOperationApplyResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenSpOperationApplyResponseModel" /> class.
        /// </summary>
        /// <param name="batchNo">支付宝操作批次号.</param>
        /// <param name="bindAccount">bindAccount.</param>
        /// <param name="recommendAccounts">只针对服务商代间连商家发起代运营绑定、授权时，如果传递的alipay_account不符合绑定或授权要求，这个字段会返回推荐的商家支付宝账号列表，包括：支付宝账号和名称，为保护商家信息，账号和名称都按照规范脱敏。.</param>
        public AlipayOpenSpOperationApplyResponseModel(string batchNo = default(string), RecommendAccountDTO bindAccount = default(RecommendAccountDTO), List<RecommendAccountDTO> recommendAccounts = default(List<RecommendAccountDTO>))
        {
            this.BatchNo = batchNo;
            this.BindAccount = bindAccount;
            this.RecommendAccounts = recommendAccounts;
        }

        /// <summary>
        /// 支付宝操作批次号
        /// </summary>
        /// <value>支付宝操作批次号</value>
        [DataMember(Name = "batch_no", EmitDefaultValue = false)]
        public string BatchNo { get; set; }

        /// <summary>
        /// Gets or Sets BindAccount
        /// </summary>
        [DataMember(Name = "bind_account", EmitDefaultValue = false)]
        public RecommendAccountDTO BindAccount { get; set; }

        /// <summary>
        /// 只针对服务商代间连商家发起代运营绑定、授权时，如果传递的alipay_account不符合绑定或授权要求，这个字段会返回推荐的商家支付宝账号列表，包括：支付宝账号和名称，为保护商家信息，账号和名称都按照规范脱敏。
        /// </summary>
        /// <value>只针对服务商代间连商家发起代运营绑定、授权时，如果传递的alipay_account不符合绑定或授权要求，这个字段会返回推荐的商家支付宝账号列表，包括：支付宝账号和名称，为保护商家信息，账号和名称都按照规范脱敏。</value>
        [DataMember(Name = "recommend_accounts", EmitDefaultValue = false)]
        public List<RecommendAccountDTO> RecommendAccounts { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenSpOperationApplyResponseModel {\n");
            sb.Append("  BatchNo: ").Append(BatchNo).Append("\n");
            sb.Append("  BindAccount: ").Append(BindAccount).Append("\n");
            sb.Append("  RecommendAccounts: ").Append(RecommendAccounts).Append("\n");
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
            return this.Equals(input as AlipayOpenSpOperationApplyResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenSpOperationApplyResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenSpOperationApplyResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenSpOperationApplyResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.BatchNo == input.BatchNo ||
                    (this.BatchNo != null &&
                    this.BatchNo.Equals(input.BatchNo))
                ) && 
                (
                    this.BindAccount == input.BindAccount ||
                    (this.BindAccount != null &&
                    this.BindAccount.Equals(input.BindAccount))
                ) && 
                (
                    this.RecommendAccounts == input.RecommendAccounts ||
                    this.RecommendAccounts != null &&
                    input.RecommendAccounts != null &&
                    this.RecommendAccounts.SequenceEqual(input.RecommendAccounts)
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
                if (this.BatchNo != null)
                {
                    hashCode = (hashCode * 59) + this.BatchNo.GetHashCode();
                }
                if (this.BindAccount != null)
                {
                    hashCode = (hashCode * 59) + this.BindAccount.GetHashCode();
                }
                if (this.RecommendAccounts != null)
                {
                    hashCode = (hashCode * 59) + this.RecommendAccounts.GetHashCode();
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
