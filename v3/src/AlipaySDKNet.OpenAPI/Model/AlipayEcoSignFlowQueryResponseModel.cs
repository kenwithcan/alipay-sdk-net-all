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
    /// AlipayEcoSignFlowQueryResponseModel
    /// </summary>
    [DataContract(Name = "AlipayEcoSignFlowQueryResponseModel")]
    public partial class AlipayEcoSignFlowQueryResponseModel : IEquatable<AlipayEcoSignFlowQueryResponseModel>, IValidatableObject
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AlipayEcoSignFlowQueryResponseModel" /> class.
        /// </summary>
        /// <param name="businessScene">文件主题.</param>
        /// <param name="contractValidity">文件有效截止日期.</param>
        /// <param name="flowDesc">流程描述, 如果流程已拒签或已撤回, 并且存在拒签或撤回原因, 流程描述显示为原因, 否则默认为流程状态描述.</param>
        /// <param name="flowEndTime">流程结束时间.</param>
        /// <param name="flowId">流程Id.</param>
        /// <param name="flowStartTime">流程开始时间.</param>
        /// <param name="flowStatus">流程状态,0-草稿 1-签署中 2-完成 3-撤销 4-终止 5-过期 6-删除 7-拒签.</param>
        /// <param name="noticeDeveloperUrl">通知开发者地址.</param>
        /// <param name="signValidity">签署有效截止日期.</param>
        /// <param name="signers">签署人列表及签署状态.</param>
        public AlipayEcoSignFlowQueryResponseModel(string businessScene = default(string), int contractValidity = default(int), string flowDesc = default(string), int flowEndTime = default(int), string flowId = default(string), int flowStartTime = default(int), int flowStatus = default(int), string noticeDeveloperUrl = default(string), int signValidity = default(int), List<FlowSigner> signers = default(List<FlowSigner>))
        {
            this.BusinessScene = businessScene;
            this.ContractValidity = contractValidity;
            this.FlowDesc = flowDesc;
            this.FlowEndTime = flowEndTime;
            this.FlowId = flowId;
            this.FlowStartTime = flowStartTime;
            this.FlowStatus = flowStatus;
            this.NoticeDeveloperUrl = noticeDeveloperUrl;
            this.SignValidity = signValidity;
            this.Signers = signers;
        }

        /// <summary>
        /// 文件主题
        /// </summary>
        /// <value>文件主题</value>
        [DataMember(Name = "business_scene", EmitDefaultValue = false)]
        public string BusinessScene { get; set; }

        /// <summary>
        /// 文件有效截止日期
        /// </summary>
        /// <value>文件有效截止日期</value>
        [DataMember(Name = "contract_validity", EmitDefaultValue = false)]
        public int ContractValidity { get; set; }

        /// <summary>
        /// 流程描述, 如果流程已拒签或已撤回, 并且存在拒签或撤回原因, 流程描述显示为原因, 否则默认为流程状态描述
        /// </summary>
        /// <value>流程描述, 如果流程已拒签或已撤回, 并且存在拒签或撤回原因, 流程描述显示为原因, 否则默认为流程状态描述</value>
        [DataMember(Name = "flow_desc", EmitDefaultValue = false)]
        public string FlowDesc { get; set; }

        /// <summary>
        /// 流程结束时间
        /// </summary>
        /// <value>流程结束时间</value>
        [DataMember(Name = "flow_end_time", EmitDefaultValue = false)]
        public int FlowEndTime { get; set; }

        /// <summary>
        /// 流程Id
        /// </summary>
        /// <value>流程Id</value>
        [DataMember(Name = "flow_id", EmitDefaultValue = false)]
        public string FlowId { get; set; }

        /// <summary>
        /// 流程开始时间
        /// </summary>
        /// <value>流程开始时间</value>
        [DataMember(Name = "flow_start_time", EmitDefaultValue = false)]
        public int FlowStartTime { get; set; }

        /// <summary>
        /// 流程状态,0-草稿 1-签署中 2-完成 3-撤销 4-终止 5-过期 6-删除 7-拒签
        /// </summary>
        /// <value>流程状态,0-草稿 1-签署中 2-完成 3-撤销 4-终止 5-过期 6-删除 7-拒签</value>
        [DataMember(Name = "flow_status", EmitDefaultValue = false)]
        public int FlowStatus { get; set; }

        /// <summary>
        /// 通知开发者地址
        /// </summary>
        /// <value>通知开发者地址</value>
        [DataMember(Name = "notice_developer_url", EmitDefaultValue = false)]
        public string NoticeDeveloperUrl { get; set; }

        /// <summary>
        /// 签署有效截止日期
        /// </summary>
        /// <value>签署有效截止日期</value>
        [DataMember(Name = "sign_validity", EmitDefaultValue = false)]
        public int SignValidity { get; set; }

        /// <summary>
        /// 签署人列表及签署状态
        /// </summary>
        /// <value>签署人列表及签署状态</value>
        [DataMember(Name = "signers", EmitDefaultValue = false)]
        public List<FlowSigner> Signers { get; set; }

        /// <summary>
        /// Returns the string presentation of the object
        /// </summary>
        /// <returns>String presentation of the object</returns>
        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("class AlipayEcoSignFlowQueryResponseModel {\n");
            sb.Append("  BusinessScene: ").Append(BusinessScene).Append("\n");
            sb.Append("  ContractValidity: ").Append(ContractValidity).Append("\n");
            sb.Append("  FlowDesc: ").Append(FlowDesc).Append("\n");
            sb.Append("  FlowEndTime: ").Append(FlowEndTime).Append("\n");
            sb.Append("  FlowId: ").Append(FlowId).Append("\n");
            sb.Append("  FlowStartTime: ").Append(FlowStartTime).Append("\n");
            sb.Append("  FlowStatus: ").Append(FlowStatus).Append("\n");
            sb.Append("  NoticeDeveloperUrl: ").Append(NoticeDeveloperUrl).Append("\n");
            sb.Append("  SignValidity: ").Append(SignValidity).Append("\n");
            sb.Append("  Signers: ").Append(Signers).Append("\n");
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
            return this.Equals(input as AlipayEcoSignFlowQueryResponseModel);
        }

        /// <summary>
        /// Returns true if AlipayEcoSignFlowQueryResponseModel instances are equal
        /// </summary>
        /// <param name="input">Instance of AlipayEcoSignFlowQueryResponseModel to be compared</param>
        /// <returns>Boolean</returns>
        public bool Equals(AlipayEcoSignFlowQueryResponseModel input)
        {
            if (input == null)
            {
                return false;
            }
            return 
                (
                    this.BusinessScene == input.BusinessScene ||
                    (this.BusinessScene != null &&
                    this.BusinessScene.Equals(input.BusinessScene))
                ) && 
                (
                    this.ContractValidity == input.ContractValidity ||
                    this.ContractValidity.Equals(input.ContractValidity)
                ) && 
                (
                    this.FlowDesc == input.FlowDesc ||
                    (this.FlowDesc != null &&
                    this.FlowDesc.Equals(input.FlowDesc))
                ) && 
                (
                    this.FlowEndTime == input.FlowEndTime ||
                    this.FlowEndTime.Equals(input.FlowEndTime)
                ) && 
                (
                    this.FlowId == input.FlowId ||
                    (this.FlowId != null &&
                    this.FlowId.Equals(input.FlowId))
                ) && 
                (
                    this.FlowStartTime == input.FlowStartTime ||
                    this.FlowStartTime.Equals(input.FlowStartTime)
                ) && 
                (
                    this.FlowStatus == input.FlowStatus ||
                    this.FlowStatus.Equals(input.FlowStatus)
                ) && 
                (
                    this.NoticeDeveloperUrl == input.NoticeDeveloperUrl ||
                    (this.NoticeDeveloperUrl != null &&
                    this.NoticeDeveloperUrl.Equals(input.NoticeDeveloperUrl))
                ) && 
                (
                    this.SignValidity == input.SignValidity ||
                    this.SignValidity.Equals(input.SignValidity)
                ) && 
                (
                    this.Signers == input.Signers ||
                    this.Signers != null &&
                    input.Signers != null &&
                    this.Signers.SequenceEqual(input.Signers)
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
                if (this.BusinessScene != null)
                {
                    hashCode = (hashCode * 59) + this.BusinessScene.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.ContractValidity.GetHashCode();
                if (this.FlowDesc != null)
                {
                    hashCode = (hashCode * 59) + this.FlowDesc.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.FlowEndTime.GetHashCode();
                if (this.FlowId != null)
                {
                    hashCode = (hashCode * 59) + this.FlowId.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.FlowStartTime.GetHashCode();
                hashCode = (hashCode * 59) + this.FlowStatus.GetHashCode();
                if (this.NoticeDeveloperUrl != null)
                {
                    hashCode = (hashCode * 59) + this.NoticeDeveloperUrl.GetHashCode();
                }
                hashCode = (hashCode * 59) + this.SignValidity.GetHashCode();
                if (this.Signers != null)
                {
                    hashCode = (hashCode * 59) + this.Signers.GetHashCode();
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
