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
    /// AlipayOpenAgentCreateResponseModel
    /// </summary>
    [DataContract(Name = "AlipayOpenAgentCreateResponseModel")]
    public partial class AlipayOpenAgentCreateResponseModel : IEquatable<AlipayOpenAgentCreateResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayOpenAgentCreateResponseModel" /> class.
        /// </summary>
        /// <param name="batchNo">本次代商户操作的全局唯一事务编号，后续代商户创建小程序、代签约当面付等产品、提交事务等接口都需要传递该batch_no值，且要确认只有 init 状态的batch_no才能发起调用。.</param>
        /// <param name="batchStatus">ISV 代商户操作事务状态，事务状态包括：  init&#x3D;初始状态，本接口alipay.open.agent.create返回 init 状态，只有init状态允许进行各种业务接口调用；  submit&#x3D;提交状态，事务已经到达终态，调用alipay.open.agent.confirm接口可以提交init状态的事务  cancel&#x3D;取消状态，事务已经到达终态，调用alipay.open.agent.cancel接口可以取消init状态的事务  timeout&#x3D;超时状态，事务已经到达终态，init状态的事务，在【1个小时】后会自动超时  注意：只有 init 状态才允许进行接口调用，其它状态都是终态，不允许继续进行接口调用。.</param>
        public AlipayOpenAgentCreateResponseModel(string batchNo = default(string), string batchStatus = default(string))
        {
            this.BatchNo = batchNo;
            this.BatchStatus = batchStatus;
        }

        /// <summary>
        /// 本次代商户操作的全局唯一事务编号，后续代商户创建小程序、代签约当面付等产品、提交事务等接口都需要传递该batch_no值，且要确认只有 init 状态的batch_no才能发起调用。
        /// </summary>
        /// <value>本次代商户操作的全局唯一事务编号，后续代商户创建小程序、代签约当面付等产品、提交事务等接口都需要传递该batch_no值，且要确认只有 init 状态的batch_no才能发起调用。</value>
        [DataMember(Name = "batch_no", EmitDefaultValue = false)]
        public string BatchNo { get; set; }

        /// <summary>
        /// ISV 代商户操作事务状态，事务状态包括：  init&#x3D;初始状态，本接口alipay.open.agent.create返回 init 状态，只有init状态允许进行各种业务接口调用；  submit&#x3D;提交状态，事务已经到达终态，调用alipay.open.agent.confirm接口可以提交init状态的事务  cancel&#x3D;取消状态，事务已经到达终态，调用alipay.open.agent.cancel接口可以取消init状态的事务  timeout&#x3D;超时状态，事务已经到达终态，init状态的事务，在【1个小时】后会自动超时  注意：只有 init 状态才允许进行接口调用，其它状态都是终态，不允许继续进行接口调用。
        /// </summary>
        /// <value>ISV 代商户操作事务状态，事务状态包括：  init&#x3D;初始状态，本接口alipay.open.agent.create返回 init 状态，只有init状态允许进行各种业务接口调用；  submit&#x3D;提交状态，事务已经到达终态，调用alipay.open.agent.confirm接口可以提交init状态的事务  cancel&#x3D;取消状态，事务已经到达终态，调用alipay.open.agent.cancel接口可以取消init状态的事务  timeout&#x3D;超时状态，事务已经到达终态，init状态的事务，在【1个小时】后会自动超时  注意：只有 init 状态才允许进行接口调用，其它状态都是终态，不允许继续进行接口调用。</value>
        [DataMember(Name = "batch_status", EmitDefaultValue = false)]
        public string BatchStatus { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayOpenAgentCreateResponseModel {\n");
            sb.Append("  BatchNo: ").Append(BatchNo).Append("\n");
            sb.Append("  BatchStatus: ").Append(BatchStatus).Append("\n");
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
            return this.Equals(input as AlipayOpenAgentCreateResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayOpenAgentCreateResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayOpenAgentCreateResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayOpenAgentCreateResponseModel input)
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
                    this.BatchStatus == input.BatchStatus ||
                    (this.BatchStatus != null &&
                    this.BatchStatus.Equals(input.BatchStatus))
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
                if (this.BatchStatus != null)
                {
                    hashCode = (hashCode * 59) + this.BatchStatus.GetHashCode();
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
